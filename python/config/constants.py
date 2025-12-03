CREATE_STATUS_OKAY_HASH = "70e90d8c31e2474785532a34bd27d73c"
CREATE_STATUS_OBJECT_NAME_NOT_FOUND = "a6b55c269a3833d2538afbb0141fa71d"
CREATE_STATUS_OBJECT_NAME_COLLISION = "e80a14038bfaaa53f468ce886f52678a"
STATUS_PENDING = "25dda1439b810679a85164000ac6b858"
READ_HASH = "3466fab4975481651940ed328aa990e4"
WRITE_HASH = "d4b9e47f65b6e79b010582f15785867e"
QUERY_INFO_STATUS_OKAY_HASH = "1d4da69b0cdabfc134cbc7a4df238514"
WRITE_STATUS_OKAY_HASH = "f67479816abbd6532e37f29dc44a3658"
SET_INFO_STATUS_OKAY_HASH = "bf48e5a6f9a8a73fd2d9e262ca77ed2d"





# FILE_NOTIFY_INFORMATION
# Actions
FILE_ACTION_ADDED = 0x00000001
FILE_ACTION_REMOVED = 0x00000002
FILE_ACTION_MODIFIED = 0x00000003
FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
FILE_ACTION_RENAMED_NEW_NAME = 0x00000005

FILE_ACTIONS = {
    0x00000001: "FILE_ACTION_ADDED",
    0x00000002: "FILE_ACTION_REMOVED",
    0x00000003: "FILE_ACTION_MODIFIED",
    0x00000004: "FILE_ACTION_RENAMED_OLD_NAME",
    0x00000005: "FILE_ACTION_RENAMED_NEW_NAME",
}

FileSystemInformationClasses = {
    0x01: "FileFsVolumeInformation",
    0x02: "FileFsLabelInformation",
    0x03: "FileFsSizeInformation",
    0x04: "FileFsDeviceInformation",
    0x05: "FileFsAttributeInformation",
    0x06: "FileFsControlInformation",
    0x07: "FileFsFullSizeInformation",
    0x08: "FileFsObjectIdInformation",
    0x09: "FileFsDriverPathInformation",
    0x0A: "FileFsVolumeFlagsInformation",
    0x0B: "FileFsSectorSizeInformation",
}

DISPOSITION_STRINGS = {
    0x00000000: "FILE_SUPERSEDE",
    0x00000001: "FILE_OPEN",
    0x00000002: "FILE_CREATE",
    0x00000003: "FILE_OPEN_IF",
    0x00000004: "FILE_OVERWRITE",
    0x00000005: "FILE_OVERWRITE_IF",
}

# CopyFileA = TO SERVER
# CopyFileB = FROM SERVER
# CopyFileC = FROM TO SERVER
SMB_FINGERPRINT_HASHES = {
    # against a directory
    "ef75d76a1f1466f1a4a5db800ee78898" : ["CopyFileA", "MoveFileA", "cmd echo new file"],
    "b01f615be3eff89ae81263976f8fa5f2" : ["cmd autocomplete dir"],
    "d419d29b2ed383b3a6894c04cee18002" : ["cmd autocomplete dir", "cmd autocomplete file"],
    "5cc7f86ea2ac62e9368ac060a98d70cf" : ["cmd autocomplete dir"],
    # against the target file
    "216b9f88d3905dea12ccfd2e54950d2f" : ["CopyFileA"],
    "3b3965c0e9a9edd75a59260d6aaf546a" : ["??"],
    "7c6a74e0ea48e6df13a2d4a48ebb1aca" : ["??"],
    "613093a6b901447abf169b70a47f857d" : ["CopyFileB"],
    "30ad6e298b55afcef16aed3db5aad281" : ["MoveFileA"],
    "91abc1b07ef95e3282e9bbf84d0b1936" : ["MoveFileA"],
    "f50a93626be002266a5d6f48a529e8d4" : ["MoveFileB"],
    "dff35ce9c342da913b5c6aceb8476c3b" : ["GetFileAttributes"],
    "8cd1d68df2405b3f27af47a1ce2ad01e" : ["FindFirstFile"],
    "df5afa774cb733009f67b645e71bc3ab" : ["SetFileAttributes"],
    "4462abbda1a28116ca01c05ed809f012" : ["DeleteFile", "MoveFileB"],
    "dd782113b86290b12908ee9238aee2a8" : ["CreateDirectory"],
    "df9e2387b4ef9ce5ce35c20ca34d48b7" : ["RemoveDirectory"],
    "ac88b9f7c4b172404ea0d5c9f8cca9b9" : ["cmd echo new file"],
    "6b9a4dbcedfb88ee5f0c67fada0b1655" : ["MoveFileB", "cmd rename file"],
    "eb7356add9636ffd111f9a852a719c43" : ["cmd type file", "cmd more file"],
}


SMB_FINGERPRINT_HASHES_NO_EXTRA = {
    # against a directory
    "d44ed69a089a9e12b563024d274e80ae" : ["CreateDirectory"],
    "5e29a2fc18fd4157860033d17489b3d0" : ["RemoveDirectory"],
    "82c0d4f6b037bf74c9021f13939f4c08" : ["CopyFileA", "MoveFileA"],
   
    # against the target file
    "d18b0f4425610e8b761603c90c649eab" : ["CopyFileA"],
    "0dc83fc150152ae78a9fd335d2709655" : ["CopyFileB"],
    "cdcdc04c91da78dd23be82d326756f83" : ["MoveFileA"],
    "8b71bb9e617608702d4e754dc84810f3" : ["MoveFileA"],
    "1570530b9394ecc14eb0865cbdb2f42d" : ["MoveFileB", "cmd rename file"],
    "1dd98c26105f7dc3f743b63ac6ea7a58" : ["MoveFileB"],
    "f80af69702c36878c8139b0b13fcd28a" : ["MoveFileB"],
    "2315a0ed1155ac1c825225e39cf5b2df" : ["GetFileAttributes"],
    "99136326c5e92189514e8f40972a18d2" : ["FindFirstFile"],
    "f80af69702c36878c8139b0b13fcd28a" : ["DeleteFile", "MoveFileB"],
    "50aa41bdf7ea5bb8b6d1f7eb004b5c4b" : ["SetFileAttributes"],

    "c61773ccb3f50beb9605440da373fa90" : ["cmd copy file B"],
}


SMB_SHARE_INFORMATION_TMP = dict()
SMB_EXTRACTED_SHARES = dict()
SMB_EXTRACTED_QUERY_REQUESTS = dict()