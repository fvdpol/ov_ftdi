from ovplatform.ov3 import Platform
from targets.ov3_main import OV3
from targets.ov3_ftdi_tests import FTDILoopback, FTDITXRamp
import check_timing

import sys
import argparse
import os
import json
import platform
import zipfile
import shutil
import subprocess


# Buildable tops (FPGA bitstreams)
TARGETS = {
    'ov3': OV3,
    'ftdi_loopback': FTDILoopback,
    'ftdi_txramp': FTDITXRamp,
}


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-t', '--target', default='ov3', choices=sorted(TARGETS),
                   help='Which top to build.')
    p.add_argument('-d', '--build-dir', default='build', help='Override build directory.')
    p.add_argument('-n', '--build-name', default='ov3', help='Override build name.')
    p.add_argument('-p', '--generate-fwpkg', action='store_true', default=False, help='Generate firmware package after build finishes.')
    p.add_argument('-m', '--mibuild-params', default='{}', type=json.loads, help='Extra mibuild parameters (in JSON).')
    p.add_argument('--min-slack', type=float, default=0.3, help='Minimum required timing slack in ns for the post-build trce check.')
    return p.parse_args()


def setup_ise_environment():
    """Ensure all Xilinx ISE 14.7 tools can be called.

    Migen build requires following tools: xst, ngdbuild, map, par, bitgen.
    After build we generate timing report with: trce.

    The tools are normally sourced with /opt/Xilinx/14.7/ISE_DS/settings64.sh or
    /opt/Xilinx/14.7/ISE_DS/settings32.sh.
    When the settings are sourced, host side tools that use libusb are likely
    to break due to libusb version mismatch between host and Xilinx ISE 14.7.
    Therefore the build scripts checks if all the tools are callable, and if not
    then it prepends PATH/LD_LIBRARY_PATH only within build process environment,
    leaving caller's environment (e.g. make) intact.
    """
    ise_tools = ("xst", "ngdbuild", "map", "par", "bitgen", "trce")
    if all(shutil.which(tool) for tool in ise_tools):
        return

    arch = "lin64" if platform.machine() in ("x86_64", "amd64", "AMD64") else "lin"

    ise_ds = os.environ.get("XILINX_ISE_DS", "/opt/Xilinx/14.7/ISE_DS")
    xilinx = os.path.join(ise_ds, "ISE")
    edk = os.path.join(ise_ds, "EDK")
    planahead = os.path.join(ise_ds, "PlanAhead")
    common = os.path.join(ise_ds, "common")
    lmc_home = os.path.join(xilinx, "smartmodel", arch, "installed_" + arch)

    os.environ["XILINX"] = xilinx
    os.environ["XILINX_DSP"] = xilinx
    os.environ["XILINX_EDK"] = edk
    os.environ["XILINX_PLANAHEAD"] = planahead
    os.environ["LMC_HOME"] = lmc_home

    def prepend(var, paths):
        existing = os.environ.get(var)
        if existing:
            paths = paths + [existing]
        os.environ[var] = os.pathsep.join(paths)

    prepend("PATH", [
        os.path.join(xilinx, "bin", arch),
        os.path.join(xilinx, "sysgen", "util"),
        os.path.join(xilinx, "sysgen", "bin"),
        os.path.join(planahead, "bin"),
        os.path.join(edk, "bin", arch),
        os.path.join(common, "bin", arch),
    ])
    prepend("LD_LIBRARY_PATH", [
        os.path.join(xilinx, "lib", arch),
        os.path.join(lmc_home, "lib"),
        os.path.join(xilinx, "sysgen", "lib"),
        os.path.join(edk, "lib", arch),
        os.path.join(common, "lib", arch),
    ])


def run_timing_check(build_dir, build_name, min_slack):
    """Run trce on the placed-and-routed design and verify the slack margin.

    Generate build_name.twr in build_dir and check it via check_timing.
    Return check's exit code (non-zero on failure).
    """
    twr = build_name + ".twr"
    subprocess.check_call(
        ["trce", "-v", "3", "-o", twr, build_name + ".ncd", build_name + ".pcf"],
        cwd=build_dir)
    return check_timing.check_report(os.path.join(build_dir, twr), min_slack)


def gen_mapfile(ov3_mod):
    # Generate mapfile for tool / sw usage
    r = ""
    for name, csrs, mapaddr, rmap in sorted(
            ov3_mod.csrbankarray.banks, key=lambda x: x[2]):
        r += "\n# "+name+"\n"
        reg_base = 0x200 * mapaddr
        r += name.upper()+"_BASE = "+hex(reg_base)+"\n"

        for n, csr in enumerate(csrs):
            nr = (csr.size + 7)//8
            if nr == 1:
                r += "%s = %#x\n" % ((name + "_" + csr.name).upper(), reg_base)
            else:
                r += "%s = %#x:%#x\n" % ((name + "_" + csr.name).upper(), reg_base, reg_base + nr - 1)
            reg_base += nr

    return r


if __name__ == "__main__":
    args = parse_args()

    setup_ise_environment()

    mibuild_params = {
        'build_dir': args.build_dir,
        'build_name': args.build_name,
    }

    if len(args.mibuild_params) != 0:
        mibuild_params.update(args.mibuild_params)

    plat = Platform()
    top = TARGETS[args.target](plat)

    # Test bitstreams may not have CSR registers
    has_csr_map = hasattr(top, "csrbankarray")

    if args.generate_fwpkg and not has_csr_map:
        raise Exception("Target %s does not support fwpkg" % (args.target))

    os.makedirs(args.build_dir, exist_ok=True)

    # Paths
    bit_file_name = args.build_name + '.bit'
    map_file_path = os.path.join(args.build_dir, "map.txt")
    bit_file_path = os.path.join(args.build_dir, bit_file_name)
    fwpkg_file_path = os.path.join(args.build_dir, args.build_name + '.fwpkg')

    # Build the register map
    if has_csr_map:
        open(map_file_path, "w").write(gen_mapfile(top))

    # Run the FPGA toolchain to build the bit file
    plat.build(top, **mibuild_params)

    # Run post implementation checks
    if run_timing_check(args.build_dir, args.build_name, args.min_slack):
        # Fail build that does not achieve timing closure
        sys.exit(1)

    # Generate fwpkg
    if args.generate_fwpkg and os.path.isfile(bit_file_path):
        with zipfile.ZipFile(fwpkg_file_path, 'w', compression=zipfile.ZIP_DEFLATED) as pack:
            with pack.open('map.txt', 'w') as dst, open(map_file_path, 'rb') as src:
                shutil.copyfileobj(src, dst)
            with pack.open(bit_file_name, 'w') as dst, open(bit_file_path, 'rb') as src:
                shutil.copyfileobj(src, dst)
