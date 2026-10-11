"""Automated MSI Package Builder for Veil using standard msilib."""
import os
import sys
import uuid
from pathlib import Path
import msilib
import msilib.schema
import msilib.sequence

packaging_dir = Path(__file__).resolve().parent
root_dir = packaging_dir.parent
dist_dir = root_dir / "dist"
exe_path = dist_dir / "Veil.exe"
msi_path = dist_dir / "Veil.msi"

PRODUCT_NAME = "Veil Privacy Gateway"
PRODUCT_CODE = "{5E1480B2-823E-4545-9831-294025C13D1A}"
UPGRADE_CODE = "{7C9F9204-749B-4DCE-9F75-DFB22A26FE5A}"
PRODUCT_VERSION = "0.1.0"
MANUFACTURER = "Veil Security"


def build_msi() -> Path:
    """Compiles Veil.exe into a standalone Windows MSI installer."""
    print("=" * 60)
    print("Veil Windows MSI Package Build Pipeline (Veil.msi)")
    print("=" * 60)

    if not exe_path.exists():
        raise FileNotFoundError(f"Missing required binary at {exe_path}. Build Veil.exe first.")

    dist_dir.mkdir(parents=True, exist_ok=True)
    if msi_path.exists():
        try:
            msi_path.unlink()
        except Exception:
            pass

    print(f"[1/4] Initializing MSI database for {PRODUCT_NAME} v{PRODUCT_VERSION}...")
    db = msilib.init_database(
        str(msi_path),
        msilib.schema,
        ProductName=PRODUCT_NAME,
        ProductCode=PRODUCT_CODE,
        ProductVersion=PRODUCT_VERSION,
        Manufacturer=MANUFACTURER,
    )

    print("[2/4] Populating standard execution sequence tables...")
    msilib.add_tables(db, msilib.sequence)

    # Set UpgradeCode and Product properties
    msilib.add_data(db, "Property", [
        ("UpgradeCode", UPGRADE_CODE),
        ("ARPPRODUCTICON", "VeilIcon"),
        ("ALLUSERS", "1"),
        ("ARPNOMODIFY", "1"),
    ])

    # Add Veil Icon if exists
    ico_path = packaging_dir / "veil.ico"
    if ico_path.exists():
        msilib.add_data(db, "Icon", [("VeilIcon", msilib.Binary(str(ico_path)))])

    print("[3/4] Structuring installation directory hierarchy & feature components...")
    feature = msilib.Feature(
        db,
        "VeilFeature",
        PRODUCT_NAME,
        "Local Privacy Gateway for AI Developers",
        1,
        directory="TARGETDIR",
    )

    cab = msilib.CAB("VeilCab")

    # TARGETDIR root
    target_dir = msilib.Directory(
        db, cab, None, str(root_dir), "TARGETDIR", "SourceDir", componentflags=0
    )

    # ProgramFilesFolder (64-bit target if AMD64)
    pf_id = "ProgramFiles64Folder" if msilib.AMD64 else "ProgramFilesFolder"
    pf_dir = msilib.Directory(
        db, cab, target_dir, ".", pf_id, ".", componentflags=0
    )

    # Veil installation folder
    app_dir = msilib.Directory(
        db, cab, pf_dir, "dist", "VeilDir", "Veil", componentflags=0
    )

    app_dir.start_component("VeilMainComponent", feature, flags=0, keyfile="Veil.exe")
    app_dir.add_file("Veil.exe", src=str(exe_path))

    # Add Start Menu Shortcut
    menu_dir = msilib.Directory(
        db, cab, target_dir, ".", "ProgramMenuFolder", ".", componentflags=0
    )
    veil_menu_dir = msilib.Directory(
        db, cab, menu_dir, ".", "VeilMenuDir", "Veil", componentflags=0
    )
    veil_menu_dir.start_component("VeilShortcutsComponent", feature, flags=0)

    msilib.add_data(db, "Shortcut", [
        (
            "VeilStartMenuShortcut",
            "VeilMenuDir",
            "Veil|Veil Privacy Gateway",
            "VeilMainComponent",
            "[#Veil.exe]",
            "",
            "Veil Privacy Gateway",
            0,
            "VeilIcon",
            0,
            "",
            "",
        )
    ])

    print("[4/4] Generating Cabinet file and committing MSI database...")
    cab.commit(db)
    db.Commit()

    size_mb = msi_path.stat().st_size / (1024 * 1024)
    print(f"\nSUCCESS: Generated Windows MSI Package: {msi_path} ({size_mb:.1f} MB)")
    return msi_path


if __name__ == "__main__":
    build_msi()
