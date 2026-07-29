---
title: "lnk"
description: ""
summary: ""
date: 2023-09-07T16:13:18+02:00
lastmod: 2023-09-07T16:13:18+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "lnk-module"
weight: 600
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `lnk` module parses Windows Link files (.lnk), and exposes metadata
contained in those files to YARA.

-------

## Module structure

| Field               | Type                        | Description                                                                                                                                                                                                                     |
|---------------------|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| is_lnk              | bool                        | True if the file is a LNK file.                                                                                                                                                                                                 |
| name                | string                      | A description of the shortcut that is displayed to end users to identify the purpose of the link.                                                                                                                               |
| creation_time       | integer                     | Time when the LNK file was created.                                                                                                                                                                                             |
| access_time         | integer                     | Time when the LNK file was last accessed.                                                                                                                                                                                       |
| write_time          | integer                     | Time when the LNK files was last modified.                                                                                                                                                                                      |
| file_size           | integer                     | Size of the target file in bytes. The target file is the file that this link references to. If the link target file is larger than 0xFFFFFFFF, this value specifies the least significant 32 bits of the link target file size. |
| file_attributes     | integer                     | Attributes of the link target file.                                                                                                                                                                                             |
| icon_location       | string                      | Location where the icon associated to the link is found. This is usually an EXE or DLL file that contains the icon among its resources. The specific icon to be used is indicated by the `icon_index` field.                    |
| icon_index          | integer                     | Index of the icon that is associated to the link, within an icon location.                                                                                                                                                      |
| show_command        | [ShowCommand](#showcommand) | Expected window state of an application launched by this link.                                                                                                                                                                  |
| drive_type          | [DriveType](#drivetype)     | Type of drive the link is stored on.                                                                                                                                                                                            |
| drive_serial_number | integer                     | Drive serial number of the volume the link target is stored on.                                                                                                                                                                 |
| volume_label        | string                      | Volume label of the drive the link target is stored on.                                                                                                                                                                         |
| local_base_path     | string                      | String used to construct the full path to the link target by appending the common_path_suffix field.                                                                                                                            |
| common_path_suffix  | string                      | String used to construct the full path to the link target by being appended to the local_base_path field.                                                                                                                       |
| relative_path       | string                      | Location of the link target relative to the LNK file.                                                                                                                                                                           |
| working_dir         | string                      | Path of the working directory to be used when activating the link target.                                                                                                                                                       |
| cmd_line_args       | string                      | Command-line arguments that are specified when activating the link target.                                                                                                                                                      |
| overlay_size        | integer                     | Size in bytes of any extra data appended to the LNK file.                                                                                                                                                                       |
| overlay_offset      | integer                     | Offset within the LNK file where the overlay starts.                                                                                                                                                                            |
| tracker_data        | [TrackerData](#trackerdata) | Distributed link tracker information.                                                                                                                                                                                           |
| target_id_list      | [ShellItem](#shellitem) array | Shell items parsed from the link target ID list. Describes the target of the shortcut as a chain of shell items (root folder, volume, file entry, control panel item, etc.).                                                   |

### ShellItem

These are the fields in each entry of the `target_id_list` array. Each entry
corresponds to an `ItemID` within the `LinkTargetIDList` structure defined in
the Microsoft [[MS-SHLLINK]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)
specification (section 2.2). The internal layout of each shell item is not
specified by Microsoft; the type-specific fields below follow the
reverse-engineered Windows Shell Item format documentation. Which fields are
populated depends on the shell item type (`item_type`); the raw `data` field is
always populated, so rules can match on shell item types that are not decoded
into a dedicated field. The fields are listed in order of the `item_type` they
belong to.

| Field            | Type                          | Description                                                                                                                                          |
|------------------|-------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| item_type        | [ShellItemType](#shellitemtype) | Category of the shell item, derived from its class type indicator byte. Always set for every shell item (if the class type indicator does not map to a known category, the raw byte value is stored as an unknown value). |
| data             | string                        | Raw class type specific data: all the bytes that follow the class type indicator byte. Always populated, so rules can match on shell items whose type is not decoded into a dedicated field. |
| cpl_file_path    | string                        | Path to the control panel CPL file. Populated for control panel CPL file shell items (item_type CONTROL_PANEL_CPL). This field is abused by CVE-2010-2568 to point to an arbitrary DLL. |
| root_folder_id   | string                        | Shell folder identifier (a GUID). Populated for root folder shell items (item_type ROOT_FOLDER).                                                     |
| volume_name      | string                        | Volume name. Populated for volume shell items (item_type VOLUME) that carry a name.                                                                  |
| volume_id        | string                        | Volume identifier (a GUID). Populated for volume shell items (item_type VOLUME) that carry an identifier instead of a name.                          |
| file_entry_name  | string                        | File or directory name. Populated for file entry shell items (item_type FILE_ENTRY).                                                                |
| network_location | string                        | Network location, usually a UNC path. Populated for network location shell items (item_type NETWORK_LOCATION).                                       |

#### Example

````
import "lnk"

rule lnk_suspicious_cpl_target {
    condition:
        for any item in lnk.target_id_list : (
            item.item_type == lnk.ShellItemType.CONTROL_PANEL_CPL and
            item.cpl_file_path endswith ".dll"
        )
}
````

### ShellItemType

These are the possible values for the `item_type` field of a
[ShellItem](#shellitem). The values are the class type indicators from the
Windows Shell Item format; for the volume, file entry and network location
items (whose class type indicator is a range) the value is the base of the
range.

| Name                                | Value |
|-------------------------------------|------:|
| ShellItemType.CONTROL_PANEL_CPL     |  0x00 |
| ShellItemType.CONTROL_PANEL_CATEGORY|  0x01 |
| ShellItemType.ROOT_FOLDER           |  0x1F |
| ShellItemType.VOLUME                |  0x20 |
| ShellItemType.FILE_ENTRY            |  0x30 |
| ShellItemType.NETWORK_LOCATION      |  0x40 |
| ShellItemType.COMPRESSED_FOLDER     |  0x52 |
| ShellItemType.URI                   |  0x61 |
| ShellItemType.CONTROL_PANEL         |  0x71 |
| ShellItemType.PRINTERS              |  0x72 |
| ShellItemType.COMMON_PLACES_FOLDER  |  0x73 |
| ShellItemType.USERS_FILES_FOLDER    |  0x74 |

### TrackerData

These are the fields in the `tracker_data` structure, which contains data that
can be used to resolve a link target if it is not found in its original location
when the link is resolved. This data is passed to the Link Tracking
service [[MS-DLTW]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dltw/fc649f0e-871a-431a-88b5-d5b2f80e9cc9)
to find the link target.

| Field                 | Type    |
|-----------------------|---------|
| version               | integer |
| machine_id            | string  |
| droid_volume_id       | string  |
| droid_file_id         | string  |
| droid_birth_volume_id | string  |
| droid_birth_file_id   | string  |

#### Example

````
import "lnk"

rule lnk_cdrom {
    condition:
        lnk.tracker_data.machine_id == "chris-xps"
}
````

### DriveType

These are the possible values for the `drive_type` field.

| Name                  | Value |
|-----------------------|------:|
| DriveType.UNKNOWN     |     0 |
| DriveType.NO_ROOT_DIR |     1 |
| DriveType.REMOVABLE   |     2 |
| DriveType.FIXED       |     3 |
| DriveType.REMOTE      |     4 |
| DriveType.CDROM       |     5 |
| DriveType.RAMDISK     |     6 |

#### Example

````
import "lnk"

rule lnk_cdrom {
    condition:
        lnk.drive_type == lnk.DriveType.CDROM 
}
````

### FileAttributes

| Name                               |  Value |
|------------------------------------|-------:|
| FILE_ATTRIBUTE_READONLY            | 0x0001 |
| FILE_ATTRIBUTE_HIDDEN              | 0x0002 |
| FILE_ATTRIBUTE_SYSTEM              | 0x0004 |
| FILE_ATTRIBUTE_DIRECTORY           | 0x0010 |
| FILE_ATTRIBUTE_ARCHIVE             | 0x0020 |
| FILE_ATTRIBUTE_NORMAL              | 0x0080 |
| FILE_ATTRIBUTE_TEMPORARY           | 0x0100 |
| FILE_ATTRIBUTE_SPARSE_FILE         | 0x0200 |
| FILE_ATTRIBUTE_REPARSE_POINT       | 0x0400 |
| FILE_ATTRIBUTE_COMPRESSED          | 0x0800 |
| FILE_ATTRIBUTE_OFFLINE             | 0x1000 |
| FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | 0x2000 |
| FILE_ATTRIBUTE_ENCRYPTED           | 0x4000 |

### ShowCommand

These are the possible values for the `show_command` field.

| Name                      | Value |
|---------------------------|------:|
| ShowCommand.NORMAL        |     1 |
| ShowCommand.MAXIMIZED     |     3 |
| ShowCommand.MIN_NO_ACTIVE |     7 |

#### Example

````
import "lnk"

rule lnk_maximized {
    condition:
        lnk.show_command == lnk.ShowCommand.MAXIMIZED
}
````