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
weight: 304
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `lnk` module parses Windows Link files (.lnk), and exposes metadata
contained in those files to YARA.

### Module structure

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

### TrackerData

This structure contains data that can be used to resolve a link target if it
is not found in its original location when the link is resolved. This data
is passed to the Link Tracking
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

### DriveType

| Name        | Number |
|-------------|-------:|
| UNKNOWN     |      0 |
| NO_ROOT_DIR |      1 |
| REMOVABLE   |      2 |
| FIXED       |      3 |
| REMOTE      |      4 |
| CDROM       |      5 |
| RAMDISK     |      6 |

### FileAttributes

| Name                               | Number |
|------------------------------------|-------:|
| FILE_ATTRIBUTE_READONLY            | 0x0001 |
| FILE_ATTRIBUTE_HIDDEN              | 0x0002 |
| FILE_ATTRIBUTE_SYSTEM              | 0x0004 |
| RESERVED_1                         | 0x0008 |
| FILE_ATTRIBUTE_DIRECTORY           | 0x0010 |
| FILE_ATTRIBUTE_ARCHIVE             | 0x0020 |
| RESERVED_2                         | 0x0040 |
| FILE_ATTRIBUTE_NORMAL              | 0x0080 |
| FILE_ATTRIBUTE_TEMPORARY           | 0x0100 |
| FILE_ATTRIBUTE_SPARSE_FILE         | 0x0200 |
| FILE_ATTRIBUTE_REPARSE_POINT       | 0x0400 |
| FILE_ATTRIBUTE_COMPRESSED          | 0x0800 |
| FILE_ATTRIBUTE_OFFLINE             | 0x1000 |
| FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | 0x2000 |
| FILE_ATTRIBUTE_ENCRYPTED           | 0x4000 |

### ShowCommand

| Name          | Number |
|---------------|-------:|
| NORMAL        |      1 |
| MAXIMIZED     |      3 |
| MIN_NO_ACTIVE |      7 |
