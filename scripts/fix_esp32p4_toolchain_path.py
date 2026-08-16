Import("env")

import os
import shutil


def _first_existing(paths):
    for p in paths:
        if p and os.path.isdir(p):
            return p
    return None


def _has_riscv_gcc(bin_dir):
    if not bin_dir:
        return False
    return os.path.isfile(os.path.join(bin_dir, "riscv32-esp-elf-gcc.exe"))


def _find_sysroot_dir(pkg_dir):
    candidates = [
        os.path.join(pkg_dir, "riscv32-esp-elf"),
        os.path.join(pkg_dir, "riscv32-esp-elf", "riscv32-esp-elf"),
    ]
    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "lib", "libc.a")):
            return candidate
    return candidates[0]


def _ensure_legacy_bin_layout(pkg_dir):
    """
    Some platform scripts expect <toolchain>/bin, while pioarduino's package
    currently places binaries under <toolchain>/riscv32-esp-elf/bin.
    """
    legacy_bin_dir = os.path.join(pkg_dir, "bin")
    nested_bin_dir = os.path.join(pkg_dir, "riscv32-esp-elf", "bin")

    if os.path.isfile(os.path.join(legacy_bin_dir, "riscv32-esp-elf-gcc.exe")):
        return
    if not os.path.isdir(nested_bin_dir):
        return

    os.makedirs(legacy_bin_dir, exist_ok=True)
    copied = 0
    for name in os.listdir(nested_bin_dir):
        src = os.path.join(nested_bin_dir, name)
        dst = os.path.join(legacy_bin_dir, name)
        if not os.path.isfile(src) or os.path.exists(dst):
            continue
        try:
            shutil.copy2(src, dst)
            copied += 1
        except Exception as exc:
            print("[p4-toolchain-fix] failed to copy %s -> %s: %s" % (src, dst, exc))

    if copied:
        print(
            "[p4-toolchain-fix] populated legacy bin layout: %s (%d files)"
            % (legacy_bin_dir, copied)
        )


def _configure_gcc_exec_prefix(pkg_dir):
    """
    When GCC is invoked from the compatibility <toolchain>/bin path, ensure it
    can still locate cc1/cc1plus under the nested libexec tree.
    """
    gcc_exec_prefix = os.path.join(pkg_dir, "riscv32-esp-elf", "libexec", "gcc")
    if not os.path.isdir(gcc_exec_prefix):
        return

    prefix_value = gcc_exec_prefix + os.sep
    env["ENV"]["GCC_EXEC_PREFIX"] = prefix_value
    print("[p4-toolchain-fix] GCC_EXEC_PREFIX=%s" % prefix_value)


def _ensure_legacy_bfd_plugins(pkg_dir):
    """
    binutils tools invoked from <toolchain>/bin look for LTO plugins under
    <toolchain>/lib/bfd-plugins.
    """
    src_plugins_dir = os.path.join(
        pkg_dir, "riscv32-esp-elf", "lib", "bfd-plugins"
    )
    dst_plugins_dir = os.path.join(pkg_dir, "lib", "bfd-plugins")
    if not os.path.isdir(src_plugins_dir):
        return
    if os.path.isfile(os.path.join(dst_plugins_dir, "liblto_plugin.dll")):
        return

    os.makedirs(dst_plugins_dir, exist_ok=True)
    copied = 0
    for name in os.listdir(src_plugins_dir):
        src = os.path.join(src_plugins_dir, name)
        dst = os.path.join(dst_plugins_dir, name)
        if not os.path.isfile(src) or os.path.exists(dst):
            continue
        try:
            shutil.copy2(src, dst)
            copied += 1
        except Exception as exc:
            print("[p4-toolchain-fix] failed to copy %s -> %s: %s" % (src, dst, exc))

    if copied:
        print(
            "[p4-toolchain-fix] populated legacy bfd-plugins: %s (%d files)"
            % (dst_plugins_dir, copied)
        )


def _fix_riscv_toolchain_layout():
    platform = env.PioPlatform()
    pkg_dir = platform.get_package_dir("toolchain-riscv32-esp")
    if not pkg_dir:
        print("[p4-toolchain-fix] toolchain-riscv32-esp package not found")
        return

    _ensure_legacy_bin_layout(pkg_dir)
    _ensure_legacy_bfd_plugins(pkg_dir)
    env["ENV"].pop("GCC_EXEC_PREFIX", None)

    # Some installs end up with an incomplete package layout in
    # ~/.platformio/packages/toolchain-riscv32-esp (missing sysroot headers/libs).
    # Restore it from the matching folder under ~/.platformio/tools when needed.
    core_dir = env.subst("$PROJECT_CORE_DIR")
    expected_triplet_dir = _find_sysroot_dir(pkg_dir)
    required_paths = [
        os.path.join(expected_triplet_dir, "lib", "libc.a"),
        os.path.join(expected_triplet_dir, "include", "machine", "_default_types.h"),
        os.path.join(expected_triplet_dir, "include", "sys", "config.h"),
    ]

    if not all(os.path.isfile(p) for p in required_paths):
        candidates = [
            os.path.join(
                core_dir,
                "tools",
                "toolchain-riscv32-esp",
                "riscv32-esp-elf",
                "riscv32-esp-elf",
            ),
            os.path.join(
                core_dir,
                "tools",
                "toolchain-riscv32-esp.tmp",
                "riscv32-esp-elf",
                "riscv32-esp-elf",
            ),
        ]

        restored = False
        for src_dir in candidates:
            if not os.path.isdir(src_dir):
                continue
            try:
                os.makedirs(expected_triplet_dir, exist_ok=True)
                shutil.copytree(src_dir, expected_triplet_dir, dirs_exist_ok=True)
                print(
                    "[p4-toolchain-fix] restored missing sysroot files from %s"
                    % src_dir
                )
                if all(os.path.isfile(p) for p in required_paths):
                    restored = True
                    break
            except Exception as exc:
                print(
                    "[p4-toolchain-fix] failed to restore sysroot files from %s: %s"
                    % (src_dir, exc)
                )
        if not restored:
            print(
                "[p4-toolchain-fix] warning: toolchain sysroot still incomplete under %s"
                % expected_triplet_dir
            )

    bin_candidates = [
        os.path.join(pkg_dir, "bin"),
        os.path.join(pkg_dir, "riscv32-esp-elf", "bin"),
    ]
    bin_dir = None
    for candidate in bin_candidates:
        if _has_riscv_gcc(candidate):
            bin_dir = candidate
            break
    if not bin_dir:
        bin_dir = _first_existing(bin_candidates[::-1])
    if not bin_dir:
        print("[p4-toolchain-fix] no riscv toolchain bin directory found")
        return

    env.PrependENVPath("PATH", bin_dir)
    print("[p4-toolchain-fix] PATH += %s" % bin_dir)

    # Keep detection mostly driven by ESP-IDF toolchain files.
    # Forcing CC/CXX/ASM here can interfere with CMake's configuration phase.


def _patch_missing_idf_package_dirs():
    """
    Work around a platform regression where get_package_dir() can return None
    for already-installed common ESP-IDF tools.
    """
    platform = env.PioPlatform()
    platform_cls = platform.__class__

    if getattr(platform_cls, "_pkgdir_fallback_patch_applied", False):
        return

    original_get_package_dir = platform_cls.get_package_dir
    project_core_dir = env.subst("$PROJECT_CORE_DIR")
    fallback_packages_dir = os.path.join(project_core_dir, "packages")
    tools_dir = os.path.join(project_core_dir, "tools")
    fallback_names = {
        "toolchain-riscv32-esp",
        "tool-cmake",
        "tool-ninja",
        "tool-esp-rom-elfs",
        "tool-esptoolpy",
    }
    announced = set()

    for name in fallback_names:
        dst_pkg = os.path.join(fallback_packages_dir, name)
        if os.path.isdir(dst_pkg):
            continue
        src_tool = os.path.join(tools_dir, name)
        if not os.path.isdir(src_tool):
            continue
        try:
            shutil.copytree(src_tool, dst_pkg, dirs_exist_ok=True)
            print("[p4-toolchain-fix] seeded package %s from %s" % (name, src_tool))
        except Exception as exc:
            print(
                "[p4-toolchain-fix] failed to seed package %s from %s: %s"
                % (name, src_tool, exc)
            )

    def _patched_get_package_dir(self, name, *args, **kwargs):
        normalized_name = name.split("@", 1)[0] if isinstance(name, str) else name
        pkg_dir = original_get_package_dir(self, name, *args, **kwargs)

        if normalized_name == "toolchain-riscv32-esp":
            if pkg_dir and _has_riscv_gcc(os.path.join(pkg_dir, "bin")):
                return pkg_dir

            nested_toolchain = None
            if pkg_dir:
                nested_candidate = os.path.join(pkg_dir, "riscv32-esp-elf")
                if _has_riscv_gcc(os.path.join(nested_candidate, "bin")):
                    nested_toolchain = nested_candidate
            else:
                fallback_pkg = os.path.join(fallback_packages_dir, normalized_name)
                if _has_riscv_gcc(os.path.join(fallback_pkg, "bin")):
                    return fallback_pkg
                nested_candidate = os.path.join(fallback_pkg, "riscv32-esp-elf")
                if _has_riscv_gcc(os.path.join(nested_candidate, "bin")):
                    nested_toolchain = nested_candidate

            if nested_toolchain:
                key = "%s:nested" % normalized_name
                if key not in announced:
                    print(
                        "[p4-toolchain-fix] remapped package dir for %s: %s"
                        % (normalized_name, nested_toolchain)
                    )
                    announced.add(key)
                return nested_toolchain

        if pkg_dir and not os.path.isdir(pkg_dir) and normalized_name in fallback_names:
            candidate = os.path.join(fallback_packages_dir, normalized_name)
            if os.path.isdir(candidate):
                key = "%s:missing-remap" % normalized_name
                if key not in announced:
                    print(
                        "[p4-toolchain-fix] remapped missing package dir for %s: %s -> %s"
                        % (normalized_name, pkg_dir, candidate)
                    )
                    announced.add(key)
                return candidate

        if pkg_dir:
            return pkg_dir

        if normalized_name in fallback_names:
            candidate = os.path.join(fallback_packages_dir, normalized_name)
            if os.path.isdir(candidate):
                if normalized_name not in announced:
                    print(
                        "[p4-toolchain-fix] fallback package dir for %s: %s"
                        % (normalized_name, candidate)
                    )
                    announced.add(normalized_name)
                return candidate

        return pkg_dir

    platform_cls.get_package_dir = _patched_get_package_dir
    platform_cls._pkgdir_fallback_patch_applied = True


_patch_missing_idf_package_dirs()
_fix_riscv_toolchain_layout()
