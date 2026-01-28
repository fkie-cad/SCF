@load base/protocols/conn
@load base/frameworks/input




module SMBCommandFingerprinting;

export {
    redef enum Log::ID += { MATCH_LOG, HASH_LOG };

    const DEBUG_MODE = F &redef;
    # Set to T to enable debug output (edit script or run with argument "SMBCommandFingerprinting::DEBUG_MODE=T")

    const HASH_ONLY_MODE = F &redef;
    # Set to T to enable hash-only mode - logs packet number, command, type, and hash without matching
    # (edit script or run with argument "SMBCommandFingerprinting::HASH_ONLY_MODE=T")

    const RULE_FILE = "" &redef;
    # Rule file path (REQUIRED - must be set with "SMBCommandFingerprinting::RULE_FILE=path/to/rules.tsv")

    type SMBMatchInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        application: string &log;
        description: string &log;
        filename: string &log &optional;
    };

    type SMBHashInfo: record {
        packet_num: count &log;
        command: string &log;
        request_type: string &log;
        hash: string &log;
    };

}


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                      DEFINITION: STRUCTURES                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# -----------------------------
# -           CREATE          -
# -----------------------------
type SMBCreateRequest: record {
    DesiredAccess: count &optional; #Access Mask
    FileAttributes: count &optional;
    ShareAccess: count &optional;
    CreateDisposition: count &optional;
    CreateOptions: count &optional;
    FileName: string &optional;
    hash: string &optional;
};
type SMBCreateResponse: record {
    Status: count &optional;
    hash: string &optional;
};

# ----------------------------
# -           CLOSE          -
# ----------------------------
type SMBCloseRequest: record {
    hash: string &optional;
};
type SMBCloseResponse: record {
    hash: string &optional;
};
    
# ---------------------------
# -           READ          -
# ---------------------------
type SMBReadRequest: record {
    hash: string &optional;
};
type SMBReadResponse: record {
    hash: string &optional;
};

# ----------------------------
# -           WRITE          -
# ----------------------------
type SMBWriteRequest: record {
    hash: string &optional;
};  
type SMBWriteResponse: record {
    Status: count &optional;
    hash: string &optional;
};

# --------------------------------
# -           QUERYINFO          -
# --------------------------------
type SMBQueryInfoRequest: record {
    InfoType: count &optional;
    FileInformationClass: count &optional;
    hash: string &optional;
};
type SMBQueryInfoResponse: record {
    Status: count &optional;
    hash: string &optional;
};
    
# -------------------------------------
# -           QUERYDIRECTORY          -
# -------------------------------------    
type SMBQueryDirectoryRequest: record {
    FileInformationClass: count &optional;
    hash: string &optional;
};    
type SMBQueryDirectoryResponse: record {
    hash: string &optional;
};

# ------------------------------
# -           SETINFO          -
# ------------------------------
type SMBSetInfoRequest: record {
    InfoType: count &optional;
    FileInformationClass: count &optional;
    FileName: string &optional;
    hash: string &optional;
};
type SMBSetInfoResponse: record {
    Status: count &optional;   
    FileInformationClass: count &optional;
    hash: string &optional;
};

# ----------------------------------
# -           TREECONNECT          -
# ----------------------------------    
type SMBTreeConnectRequest: record {
};
    
type SMBTreeConnectResponse: record {
};
    

# ----------------------------------
# -           TREECONNECT          -
# ---------------------------------- 
type SMBTreeDisconnectRequest: record {
};
type SMBTreeDisconnectResponse: record {
};

# --------------------------
# -       SMB PACKET       -
# --------------------------
type SMBPacketInfo: record {
    ts: time;
    uid: string;
    id: conn_id;
    is_orig: bool;
    length: count;
    smb_version: string;
    command: string;
    command_code: count;
    hash: string &optional;
    filename: string &optional;
    raw_data: string;
    is_compound_part: bool &default=F;  # Is this part of a compound command?
    compound_index: count &default=0;   # Position in compound (0=single or first)
};

# -----------------------
# -     SMB COMMAND     -
# -----------------------
type SMBCommand: record {
    ts: time;
    hash: string;
    command: string;
    filename: string &optional;
    length: count;
    is_response: bool;
    assigned: bool &default=F;
    is_compound: bool &default=F;           # Is this a compound command?
    individual_hashes: vector of string &optional;  # Individual hashes if compound
};

# --------------------------
# -        RULE            -
# --------------------------
type SignatureRule: record {
    application: string;
    description: string;
    signature: vector of string;
    excluded: set[string] &optional;
    max_skip: count &default=0;
    filename_hashes: set[string] &optional;
};

# --------------------------
# -     RULE CANDIDATE     -
# --------------------------
type RuleCandidate: record {
    rule_application: string;
    rule_description: string;
    rule_signature: vector of string;
    rule_excluded: set[string] &optional;
    rule_max_skip: count;
    rule_filename_hashes: set[string] &optional;
    start_index: count;
    current_signature_position: count;
    matched_command_indices: vector of count;
    skipped_count: count &default=0;
};

# ----------------------------
# -     PENDING MATCH        -
# ----------------------------
type PendingMatch: record {
    candidate: RuleCandidate;
    command_indices: vector of count;
    signature_length: count;
    pending_since_index: count;  # Command index when this became pending
};

# ----------------------------
# -        CONNECTION        -
# ----------------------------
type ConnectionState: record {
    conn_id: conn_id;
    commands: vector of SMBCommand;
    active_candidates: vector of RuleCandidate;
    pending_matches: vector of PendingMatch;
};



# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                        DEFINITION: CONSANTS                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# ---------------------------------------------------------
# -                       TABLES                          -
# ---------------------------------------------------------
global connection_states: table[string] of ConnectionState;
global smb_rules: table[string] of vector of SignatureRule;
global rule_match_counts: table[string] of count &default=0;
global smb_rules_raw: table[SignatureRule] of SignatureRule = table();

# Hash-only mode packet counter
global packet_counter: count = 0;

# Minimal buffering system
type BufferedPacket: record {
    c: connection;
    is_orig: bool;
    flags: string;
    seq: count;
    ack: count;
    len: count;
    payload: string;
};

global packet_buffer: vector of BufferedPacket = vector();
global rules_loaded: bool = F;


# ---------------------------------------------
# -            SMB2/3 COMMANDS                -
# ---------------------------------------------
const smb2_commands: table[count] of string = {
    [0x00] = "NEGOTIATE",
    [0x01] = "SESSION_SETUP",
    [0x02] = "LOGOFF",  
    [0x03] = "TREE_CONNECT",
    [0x04] = "TREE_DISCONNECT",
    [0x05] = "CREATE",
    [0x06] = "CLOSE",
    [0x07] = "FLUSH",
    [0x08] = "READ",
    [0x09] = "WRITE",
    [0x0A] = "LOCK",
    [0x0B] = "IOCTL",
    [0x0C] = "CANCEL",
    [0x0D] = "ECHO",
    [0x0E] = "QUERY_DIRECTORY",
    [0x0F] = "CHANGE_NOTIFY",
    [0x10] = "QUERY_INFO",
    [0x11] = "SET_INFO",
    [0x12] = "OPLOCK_BREAK"
};

# --------------------------------------------
# -          STATUS (INT -> TEXT)            -
# --------------------------------------------
const status_codes: table[count] of string = {
    [0x00000000] = "STATUS_SUCCESS",
    [0x80000005] = "STATUS_BUFFER_OVERFLOW",
    [0x80000006] = "STATUS_NO_MORE_FILES",
    [0xC0000001] = "STATUS_UNSUCCESSFUL",
    [0xC0000002] = "STATUS_NOT_IMPLEMENTED",
    [0xC0000008] = "STATUS_INVALID_HANDLE",
    [0xC0000009] = "STATUS_INVALID_PARAMETER",
    [0xC000000D] = "STATUS_INVALID_PARAMETER",
    [0xC000000F] = "STATUS_NO_SUCH_FILE",
    [0xC0000010] = "STATUS_INVALID_DEVICE_REQUEST",
    [0xC0000011] = "STATUS_END_OF_FILE",
    [0xC0000013] = "STATUS_NO_MEMORY",
    [0xC0000016] = "STATUS_MORE_PROCESSING_REQUIRED",
    [0xC0000022] = "STATUS_ACCESS_DENIED",
    [0xC0000023] = "STATUS_BUFFER_TOO_SMALL",
    [0xC0000033] = "STATUS_OBJECT_NAME_INVALID",
    [0xC0000034] = "STATUS_OBJECT_NAME_NOT_FOUND",
    [0xC0000035] = "STATUS_OBJECT_NAME_COLLISION",
    [0xC0000039] = "STATUS_OBJECT_PATH_INVALID",
    [0xC000003A] = "STATUS_OBJECT_PATH_NOT_FOUND",
    [0xC0000041] = "STATUS_OBJECT_PATH_SYNTAX_BAD",
    [0xC0000043] = "STATUS_SHARING_VIOLATION",
    [0xC0000054] = "STATUS_FILE_LOCK_CONFLICT",
    [0xC0000055] = "STATUS_LOCK_NOT_GRANTED",
    [0xC0000056] = "STATUS_DELETE_PENDING",
    [0xC000007F] = "STATUS_DISK_FULL",
    [0xC0000101] = "STATUS_DIRECTORY_NOT_EMPTY",
    [0xC0000103] = "STATUS_NOT_A_DIRECTORY",
    [0xC0000104] = "STATUS_CANCELLED",
    [0xC0000107] = "STATUS_CANNOT_DELETE",
    [0xC000011F] = "STATUS_INVALID_INFO_CLASS",
    [0xC0000120] = "STATUS_CANCELLED",
    [0xC0000121] = "STATUS_CANNOT_DELETE",
    [0xC0000122] = "STATUS_FILE_DELETED",
    [0xC0000123] = "STATUS_SPECIAL_ACCOUNT",
    [0xC0000128] = "STATUS_FILE_CLOSED",
    [0xC000014B] = "STATUS_PIPE_BROKEN",
    [0xC0000184] = "STATUS_INVALID_DEVICE_STATE",
    [0xC0000225] = "STATUS_NOT_FOUND",
    [0xC0000257] = "STATUS_PATH_NOT_COVERED",
    [0xC0000272] = "STATUS_PASSWORD_EXPIRED",
    [0xC0000373] = "STATUS_STOPPED_ON_SYMLINK"
};

# -------------------------------------------------
# -          ACCESS_MASK (INT -> TEXT)            -
# -------------------------------------------------
const access_mask_flags: table[count] of string = {
    [0x00000001] = "FILE_READ_DATA",
    [0x00000002] = "FILE_WRITE_DATA",
    [0x00000004] = "FILE_APPEND_DATA",
    [0x00000008] = "FILE_READ_EA",
    [0x00000010] = "FILE_WRITE_EA",
    [0x00000020] = "FILE_EXECUTE",
    [0x00000040] = "FILE_DELETE_CHILD",
    [0x00000080] = "FILE_READ_ATTRIBUTES",
    [0x00000100] = "FILE_WRITE_ATTRIBUTES",
    [0x00010000] = "DELETE",
    [0x00020000] = "READ_CONTROL",
    [0x00040000] = "WRITE_DAC",
    [0x00080000] = "WRITE_OWNER",
    [0x00100000] = "SYNCHRONIZE",
    [0x01000000] = "ACCESS_SYSTEM_SECURITY",
    [0x02000000] = "MAXIMUM_ALLOWED",
    [0x10000000] = "GENERIC_ALL",
    [0x20000000] = "GENERIC_EXECUTE",
    [0x40000000] = "GENERIC_WRITE",
    [0x80000000] = "GENERIC_READ"
};

# -----------------------------------------------------
# -           FILE_ATTRIBUTES (INT -> TEXT)           -
# -----------------------------------------------------
const file_attributes_flags: table[count] of string = {
    [0x00000001] = "FILE_ATTRIBUTE_READONLY",
    [0x00000002] = "FILE_ATTRIBUTE_HIDDEN",
    [0x00000004] = "FILE_ATTRIBUTE_SYSTEM",
    [0x00000010] = "FILE_ATTRIBUTE_DIRECTORY",
    [0x00000020] = "FILE_ATTRIBUTE_ARCHIVE",
    [0x00000080] = "FILE_ATTRIBUTE_NORMAL",
    [0x00000100] = "FILE_ATTRIBUTE_TEMPORARY",
    [0x00000200] = "FILE_ATTRIBUTE_SPARSE_FILE",
    [0x00000400] = "FILE_ATTRIBUTE_REPARSE_POINT",
    [0x00000800] = "FILE_ATTRIBUTE_COMPRESSED",
    [0x00001000] = "FILE_ATTRIBUTE_OFFLINE",
    [0x00002000] = "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
    [0x00004000] = "FILE_ATTRIBUTE_ENCRYPTED"
};

# --------------------------------------------------
# -           SHARE_ACCESS (INT -> TEXT)           -
# --------------------------------------------------
const share_access_flags: table[count] of string = {
    [0x00000001] = "FILE_SHARE_READ",
    [0x00000002] = "FILE_SHARE_WRITE",
    [0x00000004] = "FILE_SHARE_DELETE"
};

# ---------------------------------------------------
# -           DISPOSITION (INT -> TEXT)             -
# ---------------------------------------------------
const disposition_strings: table[count] of string = {
    [0x00000000] = "FILE_SUPERSEDE",
    [0x00000001] = "FILE_OPEN",
    [0x00000002] = "FILE_CREATE",
    [0x00000003] = "FILE_OPEN_IF",
    [0x00000004] = "FILE_OVERWRITE",
    [0x00000005] = "FILE_OVERWRITE_IF"
};

# ----------------------------------------------------
# -           CREATE_ACCESS (INT -> TEXT)            -
# ----------------------------------------------------
const create_options_flags: table[count] of string = {
    [0x00000001] = "FILE_DIRECTORY_FILE",
    [0x00000002] = "FILE_WRITE_THROUGH",
    [0x00000004] = "FILE_SEQUENTIAL_ONLY",
    [0x00000008] = "FILE_NO_INTERMEDIATE_BUFFERING",
    [0x00000010] = "FILE_SYNCHRONOUS_IO_ALERT",
    [0x00000020] = "FILE_SYNCHRONOUS_IO_NONALERT",
    [0x00000040] = "FILE_NON_DIRECTORY_FILE",
    [0x00000080] = "FILE_CREATE_TREE_CONNECTION",
    [0x00000100] = "FILE_COMPLETE_IF_OPLOCKED",
    [0x00000200] = "FILE_NO_EA_KNOWLEDGE",
    [0x00000400] = "FILE_OPEN_REMOTE_INSTANCE",
    [0x00000800] = "FILE_RANDOM_ACCESS",
    [0x00001000] = "FILE_DELETE_ON_CLOSE",
    [0x00002000] = "FILE_OPEN_BY_FILE_ID",
    [0x00004000] = "FILE_OPEN_FOR_BACKUP_INTENT",
    [0x00008000] = "FILE_NO_COMPRESSION",
    [0x00010000] = "FILE_OPEN_REQUIRING_OPLOCK",
    [0x00020000] = "FILE_DISALLOW_EXCLUSIVE",
    [0x00100000] = "FILE_RESERVE_OPFILTER",
    [0x00200000] = "FILE_OPEN_REPARSE_POINT",
    [0x00400000] = "FILE_OPEN_NO_RECALL",
    [0x00800000] = "FILE_OPEN_FOR_FREE_SPACE_QUERY"
};

# -----------------------------------------------
# -           INFO_TYPE (INT -> TEXT)           -
# -----------------------------------------------
const smb2_info_types: table[count] of string = {
    [0x01] = "SMB2_0_INFO_FILE",
    [0x02] = "SMB2_0_INFO_FILESYSTEM",
    [0x03] = "SMB2_0_INFO_SECURITY",
    [0x04] = "SMB2_0_INFO_QUOTA"
};

# --------------------------------------------------------
# -          FILE_INFORMATIO_CLASS (INT -> TEXT)         -
# --------------------------------------------------------
#Alphabetically sorted
const file_information_classes: table[count] of string = {
    [8] = "FileAccessInformation",
    [17] = "FileAlignmentInformation",
    [18] = "FileAllInformation",
    [19] = "FileAllocationInformation",
    [21] = "FileAlternateNameInformation",
    [35] = "FileAttributeTagInformation",
    [4] = "FileBasicInformation",
    [3] = "FileBothDirectoryInformation",
    [28] = "FileCompressionInformation",
    [1] = "FileDirectoryInformation",
    [13] = "FileDispositionInformation",
    [64] = "FileDispositionInformationEx",
    [7] = "FileEaInformation",
    [20] = "FileEndOfFileInformation",
    [2] = "FileFullDirectoryInformation",
    [15] = "FileFullEaInformation",
    [46] = "FileHardLinkInformation",
    [79] = "FileId64ExtdBothDirectoryInformation",
    [78] = "FileId64ExtdDirectoryInformation",
    [81] = "FileIdAllExtdBothDirectoryInformation",
    [80] = "FileIdAllExtdDirectoryInformation",
    [37] = "FileIdBothDirectoryInformation",
    [60] = "FileIdExtdDirectoryInformation",
    [38] = "FileIdFullDirectoryInformation",
    [50] = "FileIdGlobalTxDirectoryInformation",
    [59] = "FileIdInformation",
    [6] = "FileInternalInformation",
    [11] = "FileLinkInformation",
    [26] = "FileMailslotQueryInformation",
    [27] = "FileMailslotSetInformation",
    [16] = "FileModeInformation",
    [31] = "FileMoveClusterInformation",
    [9] = "FileNameInformation",
    [12] = "FileNamesInformation",
    [34] = "FileNetworkOpenInformation",
    [48] = "FileNormalizedNameInformation",
    [29] = "FileObjectIdInformation",
    [23] = "FilePipeInformation",
    [24] = "FilePipeLocalInformation",
    [25] = "FilePipeRemoteInformation",
    [14] = "FilePositionInformation",
    [32] = "FileQuotaInformation",
    [10] = "FileRenameInformation",
    [65] = "FileRenameInformationEx",
    [33] = "FileReparsePointInformation",
    [44] = "FileSfioReserveInformation",
    [45] = "FileSfioVolumeInformation",
    [40] = "FileShortNameInformation",
    [5] = "FileStandardInformation",
    [54] = "FileStandardLinkInformation",
    [22] = "FileStreamInformation",
    [36] = "FileTrackingInformation",
    [39] = "FileValidDataLengthInformation"
};

# ------------------------------------------------------
# -         INFORMATION_CLASS (INT -> TEXT)            -
# ------------------------------------------------------
const fs_information_classes: table[count] of string = {
    [1] = "FileFsVolumeInformation",
    [2] = "FileFsLabelInformation",
    [3] = "FileFsSizeInformation",
    [4] = "FileFsDeviceInformation",
    [5] = "FileFsAttributeInformation",
    [6] = "FileFsControlInformation",
    [7] = "FileFsFullSizeInformation",
    [8] = "FileFsObjectIdInformation",
    [9] = "FileFsDriverPathInformation",
    [10] = "FileFsVolumeFlagsInformation",
    [11] = "FileFsSectorSizeInformation"
};

# ------------------------------------------------------------
# -        QUERY_DIRECTORY_INFO_CLASS (INT -> TEXT)          -
# ------------------------------------------------------------
const query_directory_info_classes: table[count] of string = {
    [1] = "FileDirectoryInformation",
    [2] = "FileFullDirectoryInformation",
    [3] = "FileBothDirectoryInformation",
    [4] = "FileNamesInformation",
    [37] = "FileIdBothDirectoryInformation",
    [38] = "FileIdFullDirectoryInformation",
    [60] = "FileIdExtdDirectoryInformation",
    [63] = "FileIdExtdBothDirectoryInformation"
};


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                           HELPER FUNCTIONS                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝


# -------------------------------------
# -               DEBUG               -
# -------------------------------------
function debug_print(message: string) {
    if (DEBUG_MODE && !HASH_ONLY_MODE) {
        print message;
    }
}

# ---------------------------------------------------------------------------
# -                      INFO_CLASS DIFFERENTIATION                         -
# ---------------------------------------------------------------------------
function get_info_class_string(info_type: count, info_class: count): string {
    # If InfoType = FILESYSTEM (2), use fs_information_classes
    if (info_type == 0x02) {
        if (info_class in fs_information_classes) {
            return fs_information_classes[info_class];
        }
    }
    # Else use file_information_classes
    else if (info_class in file_information_classes) {
        return file_information_classes[info_class];
    }
    return fmt("UNKNOWN_INFO_CLASS_%d", info_class);
}

# ------------------------------------------------
# -             ACCESS_MASK PARSER               -
# ------------------------------------------------
#Concatenate for Hashing
function parse_access_mask(value: count): string {
    if (value == 0)
        return "";
    local ordered_bits: vector of count = vector(
        0x00000001,  # FILE_READ_DATA
        0x00000002,  # FILE_WRITE_DATA
        0x00000004,  # FILE_APPEND_DATA
        0x00000008,  # FILE_READ_EA
        0x00000010,  # FILE_WRITE_EA
        0x00000020,  # FILE_EXECUTE
        0x00000040,  # FILE_DELETE_CHILD
        0x00000080,  # FILE_READ_ATTRIBUTES
        0x00000100,  # FILE_WRITE_ATTRIBUTES
        0x00010000,  # DELETE
        0x00020000,  # READ_CONTROL
        0x00040000,  # WRITE_DAC
        0x00080000,  # WRITE_OWNER
        0x00100000,  # SYNCHRONIZE
        0x01000000,  # ACCESS_SYSTEM_SECURITY
        0x02000000,  # MAXIMUM_ALLOWED
    );
    local result_vec: vector of string = vector();
    for (idx in ordered_bits) {
        local bit = ordered_bits[idx];
        if ((value & bit) == bit && bit in access_mask_flags) {
            result_vec[|result_vec|] = access_mask_flags[bit];
        }
    }
    if (|result_vec| == 0)
        return "";
    
    return join_string_vec(result_vec, "+");
}

# ----------------------------------------------------
# -             FILE_ATTRIBUTE PARSER                -
# ----------------------------------------------------
#Concatenate for Hashing
function parse_file_attributes(value: count): string {
    if (value == 0)
        return "";
    local ordered_bits: vector of count = vector(
        0x00000001,  # FILE_ATTRIBUTE_READONLY
        0x00000002,  # FILE_ATTRIBUTE_HIDDEN
        0x00000004,  # FILE_ATTRIBUTE_SYSTEM
        0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
        0x00000020,  # FILE_ATTRIBUTE_ARCHIVE
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        0x00000100,  # FILE_ATTRIBUTE_TEMPORARY
        0x00000200,  # FILE_ATTRIBUTE_SPARSE_FILE
        0x00000400,  # FILE_ATTRIBUTE_REPARSE_POINT
        0x00000800,  # FILE_ATTRIBUTE_COMPRESSED
        0x00001000,  # FILE_ATTRIBUTE_OFFLINE
        0x00002000,  # FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        0x00004000   # FILE_ATTRIBUTE_ENCRYPTED
    );
    local result_vec: vector of string = vector();
    for (idx in ordered_bits) {
        local bit = ordered_bits[idx];
        if ((value & bit) == bit && bit in file_attributes_flags) {
            result_vec[|result_vec|] = file_attributes_flags[bit];
        }
    }
    if (|result_vec| == 0)
        return "";
    
    return join_string_vec(result_vec, "+");
}

# -------------------------------------------------
# -              SHARE_ACCESS PARSER              -
# -------------------------------------------------
#Concatenate for Hashing
function parse_share_access(value: count): string {
    if (value == 0)
        return "";
    local ordered_bits: vector of count = vector(
        0x00000001,  # FILE_SHARE_READ
        0x00000002,  # FILE_SHARE_WRITE
        0x00000004   # FILE_SHARE_DELETE
    );
    local result_vec: vector of string = vector();
    for (idx in ordered_bits) {
        local bit = ordered_bits[idx];
        if ((value & bit) == bit && bit in share_access_flags) {
            result_vec[|result_vec|] = share_access_flags[bit];
        }
    }
    if (|result_vec| == 0)
        return "";
    
    return join_string_vec(result_vec, "+");
}

# ---------------------------------------------------
# -              CREATE_ACCESS PARSER               -
# ---------------------------------------------------
#Concatenate for Hashing
function parse_create_options(value: count): string {
    if (value == 0)
        return "";
    local ordered_bits: vector of count = vector(
        0x00000001,  # FILE_DIRECTORY_FILE
        0x00000002,  # FILE_WRITE_THROUGH
        0x00000004,  # FILE_SEQUENTIAL_ONLY
        0x00000008,  # FILE_NO_INTERMEDIATE_BUFFERING
        0x00000010,  # FILE_SYNCHRONOUS_IO_ALERT
        0x00000020,  # FILE_SYNCHRONOUS_IO_NONALERT
        0x00000040,  # FILE_NON_DIRECTORY_FILE
        0x00000080,  # FILE_CREATE_TREE_CONNECTION
        0x00000100,  # FILE_COMPLETE_IF_OPLOCKED
        0x00000200,  # FILE_NO_EA_KNOWLEDGE
        0x00000400,  # FILE_OPEN_REMOTE_INSTANCE
        0x00000800,  # FILE_RANDOM_ACCESS
        0x00001000,  # FILE_DELETE_ON_CLOSE
        0x00002000,  # FILE_OPEN_BY_FILE_ID
        0x00004000,  # FILE_OPEN_FOR_BACKUP_INTENT
        0x00008000,  # FILE_NO_COMPRESSION
        0x00010000,  # FILE_OPEN_REQUIRING_OPLOCK
        0x00020000,  # FILE_DISALLOW_EXCLUSIVE
        0x00100000,  # FILE_RESERVE_OPFILTER
        0x00200000,  # FILE_OPEN_REPARSE_POINT
        0x00400000,  # FILE_OPEN_NO_RECALL
        0x00800000   # FILE_OPEN_FOR_FREE_SPACE_QUERY
    );
    local result_vec: vector of string = vector();
    for (idx in ordered_bits) {
        local bit = ordered_bits[idx];
        if ((value & bit) == bit && bit in create_options_flags) {
            result_vec[|result_vec|] = create_options_flags[bit];
        }
    }
    if (|result_vec| == 0)
        return "";
    
    return join_string_vec(result_vec, "+");
}

# ---------------------------------------------------
# -         GENERIC ACCESS_MASK PARSER              -
# ---------------------------------------------------
function expand_generic_access(value: count): count {
    local expanded = value;
    # GENERIC_READ (0x80000000)
    if ((value & 0x80000000) == 0x80000000) {
        expanded = expanded | 0x00000001;  # FILE_READ_DATA
        expanded = expanded | 0x00000008;  # FILE_READ_EA
        expanded = expanded | 0x00000080;  # FILE_READ_ATTRIBUTES
        expanded = expanded | 0x00020000;  # READ_CONTROL
        expanded = expanded | 0x00100000;  # SYNCHRONIZE
    }
    # GENERIC_WRITE (0x40000000) 
    if ((value & 0x40000000) == 0x40000000) {
        expanded = expanded | 0x00000002;  # FILE_WRITE_DATA
        expanded = expanded | 0x00000004;  # FILE_APPEND_DATA
        expanded = expanded | 0x00000010;  # FILE_WRITE_EA
        expanded = expanded | 0x00000100;  # FILE_WRITE_ATTRIBUTES
        expanded = expanded | 0x00020000;  # READ_CONTROL
        expanded = expanded | 0x00100000;  # SYNCHRONIZE
    }
    # GENERIC_EXECUTE (0x20000000) 
    if ((value & 0x20000000) == 0x20000000) {
        expanded = expanded | 0x00000020;  # FILE_EXECUTE
        expanded = expanded | 0x00000080;  # FILE_READ_ATTRIBUTES
        expanded = expanded | 0x00020000;  # READ_CONTROL
        expanded = expanded | 0x00100000;  # SYNCHRONIZE
    }
    # GENERIC_ALL (0x10000000) 
    if ((value & 0x10000000) == 0x10000000) {
        expanded = expanded | 0x00000001;  # FILE_READ_DATA
        expanded = expanded | 0x00000002;  # FILE_WRITE_DATA
        expanded = expanded | 0x00000004;  # FILE_APPEND_DATA
        expanded = expanded | 0x00000008;  # FILE_READ_EA
        expanded = expanded | 0x00000010;  # FILE_WRITE_EA
        expanded = expanded | 0x00000020;  # FILE_EXECUTE
        expanded = expanded | 0x00000040;  # FILE_DELETE_CHILD
        expanded = expanded | 0x00000080;  # FILE_READ_ATTRIBUTES
        expanded = expanded | 0x00000100;  # FILE_WRITE_ATTRIBUTES
        expanded = expanded | 0x00010000;  # DELETE
        expanded = expanded | 0x00020000;  # READ_CONTROL
        expanded = expanded | 0x00040000;  # WRITE_DAC
        expanded = expanded | 0x00080000;  # WRITE_OWNER
        expanded = expanded | 0x00100000;  # SYNCHRONIZE
        expanded = expanded | 0x01000000;  # ACCESS_SYSTEM_SECURITY
    }
    
    return expanded;
}

event smb_rule_line(description: Input::EventDescription, t: Input::Event, rule: SignatureRule) {
    if (|rule$signature| > 0) {
        local first_hash = rule$signature[0];
        if (first_hash !in smb_rules) {
            smb_rules[first_hash] = vector();
        }
        smb_rules[first_hash][|smb_rules[first_hash]|] = rule;
        
        debug_print(fmt("Loaded rule: %s - %s (sig: %d, skip: %d)", 
                rule$application, 
                rule$description,
                |rule$signature|,
                rule$max_skip));
    }
}



function organize_and_debug_rules() {
    debug_print("Organizing rules by first hash...");
    
    for (rule_key in smb_rules_raw) {
        local rule = smb_rules_raw[rule_key];
        if (|rule$signature| > 0) {
            local first_hash = rule$signature[0];
            
            if (first_hash !in smb_rules) {
                smb_rules[first_hash] = vector();
            }
            smb_rules[first_hash][|smb_rules[first_hash]|] = rule;
        }
    }
    
    # Print loaded rules (same debug output as before)
    debug_print("");
    debug_print("=== Loaded Rules ===");
    local total_rules = 0;
    for (hash_key in smb_rules) {
        total_rules += |smb_rules[hash_key]|;
        for (idx in smb_rules[hash_key]) {
            local r = smb_rules[hash_key][idx];
            debug_print(fmt("  %s: %s (sig: %d, skip: %d)", 
                    r$application, 
                    r$description,
                    |r$signature|,
                    r$max_skip));
        }
    }
    debug_print(fmt("Total: %d rules loaded", total_rules));
    debug_print("====================");
}

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                        ZEEK STARTING FUNCTION                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
event zeek_init() {

    if (HASH_ONLY_MODE) {
        print "Running in HASH-ONLY mode - no signature matching, only hash logging";
        Log::create_stream(SMBCommandFingerprinting::HASH_LOG,
                          [$columns=SMBHashInfo,
                           $path="smb_hashes"]);
        rules_loaded = T;  # Skip rule loading and buffering
        return;
    }

    if (RULE_FILE == "") {
        print "ERROR: No rule file specified! Please provide a rule file path using:";
        print "zeek -C -r trace.pcap smbcommandfingerprinting.zeek SMBCommandFingerprinting::RULE_FILE=path/to/rules.tsv";
        exit(1);
    }

    print fmt("Loading SMB rules from: %s", RULE_FILE);

    Input::add_event([$source=RULE_FILE,
                      $name="smb_rules_input",
                      $reader=Input::READER_ASCII,
                      $mode=Input::REREAD,
                      $fields=SignatureRule,
                      $ev=smb_rule_line]);


    Log::create_stream(SMBCommandFingerprinting::MATCH_LOG,
                      [$columns=SMBMatchInfo,
                       $path="reconstructed_commands"]);

}

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                         HELPER FUNCTIONS                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# -------------------------------------------------
# -         STATUS STRING PARSER                  -
# -------------------------------------------------
function get_status_string(status: count): string {
    if (status in status_codes) {
        return status_codes[status];
    } else {
        return fmt("UNKNOWN_STATUS_0x%08X", status);
    }
}

# ------------------------------------------------------------
# -               BIT PARSER FUNCTIONS                       -
# ------------------------------------------------------------
function parse_uint32_le(data: string, offset: count): count {
    if (offset + 4 > |data|)
        return 0;
    local b0 = bytestring_to_count(data[offset:offset+1]);
    local b1 = bytestring_to_count(data[offset+1:offset+2]);
    local b2 = bytestring_to_count(data[offset+2:offset+3]);
    local b3 = bytestring_to_count(data[offset+3:offset+4]);
    # Little Endian
    return b0 + (b1 * 256) + (b2 * 65536) + (b3 * 16777216);
}
function parse_uint16_le(data: string, offset: count): count {
    if (offset + 2 > |data|)
        return 0;
    local b0 = bytestring_to_count(data[offset:offset+1]);
    local b1 = bytestring_to_count(data[offset+1:offset+2]);
    # Little Endian
    return b0 + (b1 * 256);
}
function parse_uint8(data: string, offset: count): count {
    if (offset + 1 > |data|)
        return 0;
    return bytestring_to_count(data[offset:offset+1]);
}
function decode_utf16le(data: string): string {
    local result = "";
    local i = 0;
    while (i < |data| - 1) {
        local low_byte = data[i:i+1];
        local high_byte = data[i+1:i+2];
        # Null terminator
        if (low_byte == "\x00" && high_byte == "\x00")
            break;
        # Only if high byte = 0 (ASCII in UTF-16LE)
        if (high_byte == "\x00") {
            # Check if printable character
            local byte_val = bytestring_to_count(low_byte);
            if (byte_val >= 32 && byte_val <= 126) {
                result += low_byte; 
            }
        }   
        i += 2;
    }
    return result;
}


# ----------------------------------------------------------
# -                   CREATE MD5 HASH                      -
# ----------------------------------------------------------
function create_hash(attributes: vector of string): string {
    local concatenated_values = join_string_vec(attributes, ",");
    local hash = md5_hash(concatenated_values);
    return hash;
}

# --------------------------------------------------------------------
# -                   CREATE COMPOUND HASH                           -
# --------------------------------------------------------------------
# Calculate compound hash from individual command hashes
# Algorithm: MD5(hash1,hash2,hash3,...)
function create_compound_hash(individual_hashes: vector of string): string {
    if (|individual_hashes| == 0) {
        return "";
    }

    # Join individual hashes with commas
    local concatenated = join_string_vec(individual_hashes, ",");

    # Calculate MD5 of concatenated string
    local compound_hash = md5_hash(concatenated);

    debug_print(fmt("[COMPOUND HASH] Individual hashes: %s", concatenated));
    debug_print(fmt("[COMPOUND HASH] Compound hash: %s", compound_hash));

    return compound_hash;
}

# -----------------------------------------------------------------------------------------------------------------------------------------
# -                       EXRACT FILENAME                                                                                                 -
# -----------------------------------------------------------------------------------------------------------------------------------------
# With Filter
function get_filename_from_match_filtered(state: ConnectionState, matched_indices: vector of count, filename_hashes: set[string]): string {
    local create_filename = "";
    local setinfo_filename = "";

    debug_print(fmt("[FILENAME] Using hash filter with %d hashes", |filename_hashes|));

    for (idx_pos in matched_indices) {
        local cmd_idx = matched_indices[idx_pos];
        local cmd = state$commands[cmd_idx];

        # CREATE Requests
        if (cmd$command == "CREATE" && !cmd$is_response && cmd?$filename) {
            if (cmd$hash in filename_hashes) {
                if (create_filename == "") {
                    create_filename = cmd$filename;
                    debug_print(fmt("[FILENAME] Found CREATE filename: '%s' (hash: %s)", cmd$filename, cmd$hash));
                }
            } else {
                debug_print(fmt("[FILENAME] Skipping CREATE (hash %s not in filter)", cmd$hash));
            }
        }

        # SET_INFO Requests
        if (cmd$command == "SET_INFO" && !cmd$is_response && cmd?$filename) {
            if (cmd$hash in filename_hashes) {
                setinfo_filename = cmd$filename;
                debug_print(fmt("[FILENAME] Found SET_INFO filename: '%s' (hash: %s)", cmd$filename, cmd$hash));
            } else {
                debug_print(fmt("[FILENAME] Skipping SET_INFO (hash %s not in filter)", cmd$hash));
            }
        }

        # COMPOUND Commands - check if any individual hash matches the filter
        if (cmd$is_compound && !cmd$is_response && cmd?$filename && cmd?$individual_hashes) {
            local hash_matched = F;
            for (hash_idx in cmd$individual_hashes) {
                if (cmd$individual_hashes[hash_idx] in filename_hashes) {
                    hash_matched = T;
                    break;
                }
            }
            if (hash_matched) {
                if (create_filename == "") {
                    create_filename = cmd$filename;
                    debug_print(fmt("[FILENAME] Found COMPOUND filename: '%s' (individual hash matched filter)", cmd$filename));
                }
            } else {
                debug_print(fmt("[FILENAME] Skipping COMPOUND (no individual hash in filter)"));
            }
        }
    }
    if (create_filename != "" && setinfo_filename != "") {
        return fmt("%s -> %s", create_filename, setinfo_filename);
    }
    if (create_filename != "") {
        return create_filename;
    }
    if (setinfo_filename != "") {
        return setinfo_filename;
    }
    return "(empty or root directory)";
}
# Without filter
function get_filename_from_match(state: ConnectionState, matched_indices: vector of count): string {
    local create_filename = "";
    local setinfo_filename = "";

    debug_print("[FILENAME] Using default behavior (all CREATE, SET_INFO, and COMPOUND)");

    for (idx_pos in matched_indices) {
        local cmd_idx = matched_indices[idx_pos];
        local cmd = state$commands[cmd_idx];

        # CREATE Requests
        if (cmd$command == "CREATE" && !cmd$is_response && cmd?$filename) {
            if (create_filename == "") {
                create_filename = cmd$filename;
                debug_print(fmt("[FILENAME] Found CREATE filename: '%s' (default)", cmd$filename));
            }
        }

        # SET_INFO Requests
        if (cmd$command == "SET_INFO" && !cmd$is_response && cmd?$filename) {
            setinfo_filename = cmd$filename;
            debug_print(fmt("[FILENAME] Found SET_INFO filename: '%s' (default)", cmd$filename));
        }

        # COMPOUND Commands - extract filename if available
        if (cmd$is_compound && !cmd$is_response && cmd?$filename) {
            if (create_filename == "") {
                create_filename = cmd$filename;
                debug_print(fmt("[FILENAME] Found COMPOUND filename: '%s' (default)", cmd$filename));
            }
        }
    }

    if (create_filename != "" && setinfo_filename != "") {
        return fmt("%s -> %s", create_filename, setinfo_filename);
    }

    if (create_filename != "") {
        return create_filename;
    }

    if (setinfo_filename != "") {
        return setinfo_filename;
    }

    return "(empty or root directory)";
}


# ---------------------------------------------------------------
# -                   CLONE RULE CANDIDATES                     -
# ---------------------------------------------------------------
function clone_rule_candidate(src: RuleCandidate): RuleCandidate{
    local dst: RuleCandidate;

    dst$rule_application = src$rule_application;
    dst$rule_description = src$rule_description;
    dst$rule_max_skip = src$rule_max_skip;
    dst$start_index = src$start_index;
    dst$current_signature_position = src$current_signature_position;
    dst$skipped_count = src$skipped_count;

    if (src?$rule_excluded) {
        dst$rule_excluded = src$rule_excluded;
    }

    if (src?$rule_filename_hashes) {
        dst$rule_filename_hashes = src$rule_filename_hashes;
    }

    dst$rule_signature = vector();
    for (i in src$rule_signature)
        dst$rule_signature[|dst$rule_signature|] = src$rule_signature[i];

    dst$matched_command_indices = vector();
    for (i in src$matched_command_indices)
        dst$matched_command_indices[|dst$matched_command_indices|] = src$matched_command_indices[i];

    return dst;
}


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                          HANDLER FUNCTIONS                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# ---------------------------------------------------------------------
# -                        CREATE REQUEST                             -
# ---------------------------------------------------------------------
function handle_create_request(info: SMBPacketInfo): SMBCreateRequest {
    debug_print("");
    debug_print(fmt("=== CREATE REQUEST ==="));
    local create_req: SMBCreateRequest;
    local offset = 0;
    local payload = info$raw_data;
    # NETBIOS
    if (payload[0:1] == "\x00") {
        offset = 4;
    }
    local smb2_header_start = offset;
    local header_offset = 64;
    
    local des_acc_offset = 24 + header_offset + offset;
    local fil_att_offset = 28 + header_offset + offset;
    local sha_acc_offset = 32 + header_offset + offset;
    local cre_dis_offset = 36 + header_offset + offset;
    local cre_opt_offset = 40 + header_offset + offset;

    create_req$DesiredAccess = parse_uint32_le(payload, des_acc_offset);
    create_req$FileAttributes = parse_uint32_le(payload, fil_att_offset);
    create_req$ShareAccess = parse_uint32_le(payload, sha_acc_offset);
    create_req$CreateDisposition = parse_uint32_le(payload, cre_dis_offset);
    create_req$CreateOptions = parse_uint32_le(payload, cre_opt_offset);

    local name_offset_field = 44 + header_offset + offset;
    local name_length_field = 46 + header_offset + offset;
    
    local name_offset = parse_uint16_le(payload, name_offset_field);
    local name_length = parse_uint16_le(payload, name_length_field);
    
    if (name_length > 0) {
        local absolute_name_offset = smb2_header_start + name_offset;

        if (absolute_name_offset + name_length <= |payload|) {
            local name_bytes = payload[absolute_name_offset:absolute_name_offset + name_length];
            create_req$FileName = decode_utf16le(name_bytes);

            # If decoded filename is empty, make it more descriptive
            if (create_req$FileName == "") {
                create_req$FileName = "(empty or root directory)";
                debug_print(fmt("FileName: '(empty or root directory)' (decoded empty string)"));
            }

        } else {
            debug_print(fmt("ERROR: Name offset out of bounds! offset=%d, length=%d, payload_size=%d",
                     absolute_name_offset, name_length, |payload|));
            create_req$FileName = "<ERROR>";
        }
    } else {
        create_req$FileName = "/";
        debug_print(fmt("FileName: '/' (root of share)"));
    }
    
    local expanded_access = expand_generic_access(create_req$DesiredAccess); #Expand GENERIC_* Flags
    local desired_access_str = parse_access_mask(expanded_access); 
    local file_attributes_str = parse_file_attributes(create_req$FileAttributes);
    local share_access_str = parse_share_access(create_req$ShareAccess);
    local disposition_str = disposition_strings[create_req$CreateDisposition];
    local create_options_str = parse_create_options(create_req$CreateOptions);
    local values = vector(
        "CREATE",
        desired_access_str,
        file_attributes_str,
        share_access_str,
        disposition_str,
        create_options_str
    );
    local concatenated = join_string_vec(values, ",");
    
    create_req$hash = create_hash(values);
    
    #Print available Package Information
    debug_print(fmt("FileName: '%s'", create_req$FileName));
    debug_print(fmt("DesiredAccess (raw): %d", create_req$DesiredAccess));
    debug_print(fmt("DesiredAccess (expanded): %d", expanded_access));
    debug_print(fmt("DesiredAccess String: '%s'", desired_access_str));
    debug_print(fmt("FileAttributes: %d", create_req$FileAttributes));
    debug_print(fmt("FileAttributes String: '%s'", file_attributes_str));
    debug_print(fmt("ShareAccess: %d", create_req$ShareAccess));
    debug_print(fmt("ShareAccess String: '%s'", share_access_str));
    debug_print(fmt("CreateDisposition: %d", create_req$CreateDisposition));
    debug_print(fmt("CreateDisposition String: '%s'", disposition_str));
    debug_print(fmt("CreateOptions: %d", create_req$CreateOptions));
    debug_print(fmt("CreateOptions String: '%s'", create_options_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", create_req$hash));
    debug_print(fmt("======================"));
    
    return create_req;
}

# -----------------------------------------------------------------------
# -                        CREATE RESPONSE                              -
# -----------------------------------------------------------------------
function handle_create_response(info: SMBPacketInfo): SMBCreateResponse {
    debug_print("");
    debug_print(fmt("=== CREATE RESPONSE ==="));
    local create_resp: SMBCreateResponse;
    local offset = 0;
    local payload = info$raw_data;
    if (payload[0:1] == "\x00") {
        offset = 4;
    }
    local status_offset = offset + 8;
    create_resp$Status = parse_uint32_le(payload, status_offset);
    local Status_str = get_status_string(create_resp$Status);
    local values = vector(
        "CREATE RESPONSE",
        Status_str
    );
    create_resp$hash = create_hash(values);
    local concatenated = join_string_vec(values, ",");
    
    #Print available Package Information
    debug_print(fmt("Status: %s", create_resp$Status));
    debug_print(fmt("Status String: %s", Status_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", create_resp$hash));
    debug_print(fmt("======================="));

    return create_resp;
}

# --------------------------------------------------
# -                CLOSE REQUEST                   -
# --------------------------------------------------
function handle_close_request(info: SMBPacketInfo) {
    #Print available Package Information
    debug_print("");
    debug_print(fmt("=== CLOSE REQUEST ==="));
    debug_print(fmt("No available Information"));
    debug_print(fmt("====================="));

}

# ---------------------------------------------------
# -              CLOSE RESPONSE                     -
# ---------------------------------------------------
function handle_close_response(info: SMBPacketInfo) {
    #Print available Package Information
    debug_print("");
    debug_print(fmt("=== CLOSE RESPONSE ==="));
    debug_print(fmt("No available Information"));
    debug_print(fmt("======================"));
}

# -----------------------------------------------------------------
# -                     READ REQUEST                              -
# -----------------------------------------------------------------
function handle_read_request(info: SMBPacketInfo): SMBReadRequest {
    debug_print("");
    debug_print(fmt("=== READ REQUEST ==="));
    local read_req: SMBReadRequest;
    local values = vector(
        "READ"
    );
    read_req$hash = create_hash(values);
    
    #Print available Package Information
    debug_print(fmt("MD5 Hash: %s", read_req$hash));
    debug_print(fmt("======================"));

    return read_req;
}

# --------------------------------------------------
# -                 READ RESPONSE                  -
# --------------------------------------------------
function handle_read_response(info: SMBPacketInfo) {
    #Print available Package Information
    debug_print("");
    debug_print(fmt("=== READ RESPONSE ==="));
    debug_print(fmt("No available Information"));
    debug_print(fmt("====================="));
}

# -------------------------------------------------------------------
# -                        WRITE REQUEST                            -
# -------------------------------------------------------------------
function handle_write_request(info: SMBPacketInfo): SMBWriteRequest {
    debug_print("");
    debug_print(fmt("=== WRITE REQUEST ==="));
    local write_req: SMBWriteRequest;
    local values = vector(
        "WRITE"
    );
    
    write_req$hash = create_hash(values);
    local concatenated = join_string_vec(values, ",");
    
    #Print available Package Information
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", write_req$hash));
    debug_print(fmt("====================="));
    
    return write_req;
}

# ---------------------------------------------------------------------
# -                         WRITE RESPONSE                            -
# ---------------------------------------------------------------------
function handle_write_response(info: SMBPacketInfo): SMBWriteResponse {
    debug_print("");
    debug_print(fmt("=== WRITE RESPONSE ==="));
    local write_resp: SMBWriteResponse;
    local offset = 0;
    local payload = info$raw_data;
    if (payload[0:1] == "\x00") {
        offset = 4;
    }
    local status_offset = offset + 8;
    write_resp$Status = parse_uint32_le(payload, status_offset);
    local Status_str = get_status_string(write_resp$Status);
    local values = vector(
        "WRITE RESPONSE",
        Status_str
    );
    write_resp$hash = create_hash(values);
    local concatenated = join_string_vec(values, ",");
    
    #Print available Package Information
    debug_print(fmt("Status: %s", write_resp$Status));
    debug_print(fmt("Status String: %s", Status_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", write_resp$hash));
    debug_print(fmt("====================="));

    return write_resp;
}

# ----------------------------------------------------------------------------
# -                          QUERY_INFO REQUEST                              -
# ----------------------------------------------------------------------------
function handle_query_info_request(info: SMBPacketInfo): SMBQueryInfoRequest {
    debug_print("");
    debug_print(fmt("=== QUERY_INFO REQUEST ==="));
    local query_info_req: SMBQueryInfoRequest;
    local offset = 0;
    local payload = info$raw_data;

    if (payload[0:1] == "\x00") {
        offset = 4;
    }

    local header_offset = 64;
    local inf_typ_offset = 2 + header_offset + offset;
    local inf_cla_offset = 3 + header_offset + offset;
    
    query_info_req$InfoType = parse_uint8(payload, inf_typ_offset);
    query_info_req$FileInformationClass = parse_uint8(payload, inf_cla_offset);

    local info_type_str = smb2_info_types[query_info_req$InfoType];
    if (info_type_str == "") {
        info_type_str = fmt("UNKNOWN_INFO_TYPE_%d", query_info_req$InfoType);
    }
    local info_class_str = get_info_class_string(query_info_req$InfoType, query_info_req$FileInformationClass);

    local values = vector(
        "QUERY INFO",
        info_type_str,
        info_class_str
    );
    local concatenated = join_string_vec(values, ",");
    query_info_req$hash = create_hash(values);

    #Print available Package Information
    debug_print(fmt("InfoType: '%s'", query_info_req$InfoType));
    debug_print(fmt("InfoType String: '%s'", info_type_str));
    debug_print(fmt("FileInformationClass: '%s'", query_info_req$FileInformationClass));
    debug_print(fmt("FileInformationClass String: '%s'", info_class_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", query_info_req$hash));
    debug_print(fmt("=========================="));

    return query_info_req;
}

# ------------------------------------------------------------------------------
# -                            QUERY_INFO REPSONSE                             -
# ------------------------------------------------------------------------------
function handle_query_info_response(info: SMBPacketInfo): SMBQueryInfoResponse {
    debug_print("");
    debug_print(fmt("=== QUERY_INFO RESPONSE ==="));
    local query_info_resp: SMBQueryInfoResponse;
    local offset = 0;
    local payload = info$raw_data;
    if (payload[0:1] == "\x00") {
        offset = 4;
    }

    local status_offset = offset + 8;
    query_info_resp$Status = parse_uint32_le(payload, status_offset);
    local Status_str = get_status_string(query_info_resp$Status);  
    local values = vector(
        "QUERY INFO RESPONSE",
        Status_str
    );
    local concatenated = join_string_vec(values, ",");
    query_info_resp$hash = create_hash(values);

    #Print available Package Information
    debug_print(fmt("Status: %s", query_info_resp$Status));
    debug_print(fmt("Status String: %s", Status_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", query_info_resp$hash));
    debug_print(fmt("=========================="));


    return query_info_resp;
}

# --------------------------------------------------------------------------------------
# -                           QUERY_DIRECTORY REQUEST                                  -
# --------------------------------------------------------------------------------------
function handle_query_directory_request(info: SMBPacketInfo): SMBQueryDirectoryRequest {
    debug_print("");
    debug_print(fmt("=== QUERY_DIRECTORY REQUEST ==="));
    local query_directory_req: SMBQueryDirectoryRequest;
    local offset = 0;
    local payload = info$raw_data;
    if (payload[0:1] == "\x00") {
        offset = 4;
    }
    local header_offset = 64;
    local inf_cla_offset = 2 + header_offset + offset;
    query_directory_req$FileInformationClass = parse_uint8(payload, inf_cla_offset);
    local info_class_str = "";
    if (query_directory_req$FileInformationClass in query_directory_info_classes) {
        info_class_str = query_directory_info_classes[query_directory_req$FileInformationClass];
    } else {
        info_class_str = fmt("UNKNOWN_QUERY_DIR_CLASS_%d", query_directory_req$FileInformationClass);
    }
    local values = vector(
        "QUERY DIRECTORY",
        info_class_str
    );
    
    local concatenated = join_string_vec(values, ",");    
    query_directory_req$hash = create_hash(values);
    
    #Print available Package Information
    debug_print(fmt("FileInformationClass: '%s'", query_directory_req$FileInformationClass));
    debug_print(fmt("FileInformationClass String: '%s'", info_class_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", query_directory_req$hash));
    debug_print(fmt("==============================="));

    return query_directory_req;
}

# -------------------------------------------------------------
# -                QUERY_DIRECTORY RESPONSE                   -
# -------------------------------------------------------------
function handle_query_directory_response(info: SMBPacketInfo) {
    #Print available Package Information
    debug_print("");
    debug_print(fmt("=== QUERY_DIRECTORY RESPONSE ==="));
    debug_print(fmt("No available Information"));
    debug_print(fmt("====================="));
}

# ------------------------------------------------------------------------
# -                        SET_INFO REQUEST                              -
# ------------------------------------------------------------------------
function handle_set_info_request(info: SMBPacketInfo): SMBSetInfoRequest {
    debug_print("");
    debug_print(fmt("=== SET_INFO REQUEST ==="));
    local set_info_req: SMBSetInfoRequest;
    local offset = 0;
    local payload = info$raw_data;

    if (payload[0:1] == "\x00") {
        offset = 4;
    }

    local smb2_header_start = offset;
    local header_offset = 64;
    local inf_typ_offset = 2 + header_offset + offset;
    local inf_cla_offset = 3 + header_offset + offset;

    set_info_req$InfoType = parse_uint8(payload, inf_typ_offset);
    set_info_req$FileInformationClass = parse_uint8(payload, inf_cla_offset);


    if (set_info_req$FileInformationClass == 10 || 
        set_info_req$FileInformationClass == 65) {
        
        local buffer_length_field = 4 + header_offset + offset;
        local buffer_offset_field = 8 + header_offset + offset;
        
        local buffer_length = parse_uint32_le(payload, buffer_length_field);
        local buffer_offset = parse_uint16_le(payload, buffer_offset_field);
        
        if (buffer_length > 0) {
            local absolute_buffer_offset = smb2_header_start + buffer_offset;
            local filename_length_offset = absolute_buffer_offset + 16;
            
            if (filename_length_offset + 4 <= |payload|) {
                local filename_length = parse_uint32_le(payload, filename_length_offset);
                local filename_start = filename_length_offset + 4;
                
                if (filename_start + filename_length <= |payload|) {
                    local name_bytes = payload[filename_start:filename_start + filename_length];
                    set_info_req$FileName = decode_utf16le(name_bytes);
                } else {
                    debug_print(fmt("ERROR: Filename out of bounds!"));
                }
            }
        }
    }

    local info_type_str = smb2_info_types[set_info_req$InfoType];
    if (info_type_str == "") {
        info_type_str = fmt("UNKNOWN_INFO_TYPE_%d", set_info_req$InfoType);
    }
    
    local info_class_str = get_info_class_string(set_info_req$InfoType, set_info_req$FileInformationClass);

    local values = vector(
        "SET INFO",
        info_type_str,
        info_class_str
    );
    
    local concatenated = join_string_vec(values, ",");
    
    set_info_req$hash = create_hash(values);
    
    #Print available Package Information
    if (set_info_req?$FileName){#No Filename if Deletion
        debug_print(fmt("Filename: '%s'", set_info_req$FileName));
    }
    debug_print(fmt("InfoType: '%s'", set_info_req$InfoType));
    debug_print(fmt("InfoType String: '%s'", info_type_str));
    debug_print(fmt("FileInformationClass: '%s'", set_info_req$FileInformationClass));
    debug_print(fmt("FileInformationClass String: '%s'", info_class_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", set_info_req$hash));
    debug_print(fmt("==============================="));

    
    return set_info_req;
}

# --------------------------------------------------------------------------
# -                         SET_INFO RESPONSE                              -
# --------------------------------------------------------------------------
function handle_set_info_response(info: SMBPacketInfo): SMBSetInfoResponse {
    debug_print("");
    debug_print(fmt("=== SET_INFO RESPONSE ==="));
    local set_info_resp: SMBSetInfoResponse;
    local offset = 0;
    local payload = info$raw_data;
    
    if (payload[0:1] == "\x00") {
        offset = 4;
    }

    local status_offset = offset + 8;
    set_info_resp$Status = parse_uint32_le(payload, status_offset);
    local Status_str = get_status_string(set_info_resp$Status);
    
    local values = vector(
        "SET INFO RESPONSE",
        Status_str
    );
    local concatenated = join_string_vec(values, ",");    
    
    set_info_resp$hash = create_hash(values);


    #Print available Package Information
    debug_print(fmt("Status: %s", set_info_resp$Status));
    debug_print(fmt("Status String: %s", Status_str));
    debug_print(fmt("Concatenated values: %s", concatenated));
    debug_print(fmt("MD5 Hash: %s", set_info_resp$hash));
    debug_print(fmt("====================="));

    return set_info_resp;
}




# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                       PATTERN MATCHING ENGINE                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝


# ---------------------------------------------------------------------
# -          CHECK POSSIBLE NEW RULE CANIDATES                        -
# ---------------------------------------------------------------------
function check_for_new_candidates(conn_uid: string, cmd_index: count) {
    local state = connection_states[conn_uid];
    local cmd = state$commands[cmd_index];
    local cmd_hash = cmd$hash;
    
    if (cmd$assigned) {
        debug_print(fmt("[CHECK NEW CANDIDATES] Command %d already assigned, skipping", cmd_index));
        return;
    }
    
    debug_print(fmt("[CHECK NEW CANDIDATES] Looking for rules starting with: %s", cmd_hash));
    
    if (cmd_hash !in smb_rules)
        return;
    
    local rules = smb_rules[cmd_hash];
    debug_print(fmt("[CHECK NEW CANDIDATES] Found %d potential rules", |rules|));
    
    for (rule_idx in rules) {
        local rule = rules[rule_idx];
        
        if (rule$signature[0] != cmd_hash)
            next;
        
        local cand: RuleCandidate;
        cand$rule_application = rule$application;
        cand$rule_description = rule$description;
        cand$rule_max_skip = rule$max_skip;
        cand$start_index = cmd_index;
        cand$current_signature_position = 0;
        cand$skipped_count = 0;

        if (rule?$excluded) {
            cand$rule_excluded = rule$excluded;
        }

        if (rule?$filename_hashes) {
            cand$rule_filename_hashes = rule$filename_hashes;
        }

        cand$rule_signature = vector();
        for (sig_pos in rule$signature) {
            cand$rule_signature[|cand$rule_signature|] = rule$signature[sig_pos];
        }
        
        cand$matched_command_indices = vector();
        cand$matched_command_indices[0] = cmd_index;
        
        debug_print(fmt("[CHECK NEW CANDIDATES] %s - %s (sig length: %d)", 
                 cand$rule_application, cand$rule_description, 
                 |cand$rule_signature|));
        debug_print("[CHECK NEW CANDIDATES] Candidate signature:");
        for (debug_pos in cand$rule_signature) {
            debug_print(fmt("  pos %d: %s", debug_pos, cand$rule_signature[debug_pos]));
        }
        
        local new_idx = |state$active_candidates|;
        state$active_candidates[new_idx] = clone_rule_candidate(cand);

        local sig_join = join_string_vec(state$active_candidates[new_idx]$rule_signature, ",");
        debug_print(fmt("[CHECK NEW CANDIDATES: AFTER APPEND] idx %d desc: %s sig-md5: %s", 
                new_idx,
                state$active_candidates[new_idx]$rule_description,
                md5_hash(sig_join)));
        
        debug_print(fmt("[CHECK NEW CANDIDATES] Added candidate at index %d: %s - %s", 
                 new_idx, 
                 state$active_candidates[new_idx]$rule_application,
                 state$active_candidates[new_idx]$rule_description));
    }
    
    debug_print(fmt("[CHECK NEW CANDIDATES] Total active candidates: %d", |state$active_candidates|));
}

# ---------------------------------------------------------------------
# -                 UPDATE ACTIVE RULE CANIDATES                      -
# ---------------------------------------------------------------------
function update_active_candidates(conn_uid: string, cmd_index: count) {
    local state = connection_states[conn_uid];
    local cmd = state$commands[cmd_index];
    local cmd_hash = cmd$hash;
    
    debug_print(fmt("[UPDATE CANDIDATES] Checking %d active candidates", |state$active_candidates|));
    

    local new_candidates: vector of RuleCandidate = vector();
    
    for (idx in state$active_candidates) {
        local old = state$active_candidates[idx];
        
        debug_print(fmt("[UPDATE CANDIDATES]   Processing Candidate %d: %s - %s", 
                 idx, old$rule_application, old$rule_description));
        
        local next_pos = old$current_signature_position + 1;
        
        # Candidate already complete - keep it
        if (next_pos >= |old$rule_signature|) {
            new_candidates[|new_candidates|] = old;
            next;
        }
        
        local expected = old$rule_signature[next_pos];
        debug_print(fmt("[UPDATE CANDIDATES]     Expecting %s at pos %d", expected, next_pos));
        
        # Build updated candidate
        local updated: RuleCandidate;
        updated$rule_application = old$rule_application;
        updated$rule_description = old$rule_description;
        updated$rule_max_skip = old$rule_max_skip;
        updated$start_index = old$start_index;
        updated$current_signature_position = old$current_signature_position;
        updated$skipped_count = old$skipped_count;

        if (old?$rule_excluded) {
            updated$rule_excluded = old$rule_excluded;
        }

        if (old?$rule_filename_hashes) {
            updated$rule_filename_hashes = old$rule_filename_hashes;
        }
        
        # Deep copy signature
        updated$rule_signature = vector();
        for (sig_pos in old$rule_signature) {
            updated$rule_signature[|updated$rule_signature|] = old$rule_signature[sig_pos];
        }
        
        # Deep copy matched indices
        updated$matched_command_indices = vector();
        for (match_pos in old$matched_command_indices) {
            updated$matched_command_indices[|updated$matched_command_indices|] = old$matched_command_indices[match_pos];
        }
        
        # Check if current command matches
        if (cmd_hash == expected && !cmd$assigned) {
            debug_print(fmt("[UPDATE CANDIDATES]   MATCH! Advancing candidate"));
            updated$current_signature_position = next_pos;
            updated$matched_command_indices[|updated$matched_command_indices|] = cmd_index;
            new_candidates[|new_candidates|] = clone_rule_candidate(updated);
        }
        # Check if we can skip
        else if (updated$skipped_count < updated$rule_max_skip) {
            # Check if the current hash is in the excluded list
            if (updated?$rule_excluded && cmd_hash in updated$rule_excluded) {
                debug_print(fmt("[UPDATE CANDIDATES]   DROP candidate - hash %s is in excluded list", cmd_hash));
            } else {
                debug_print(fmt("[UPDATE CANDIDATES]   ~ SKIP (skipped: %d/%d)",
                         updated$skipped_count, updated$rule_max_skip));
                updated$skipped_count += 1;
                new_candidates[|new_candidates|] = clone_rule_candidate(updated);
            }
        }
        # Drop candidate
        else {
            debug_print(fmt("[UPDATE CANDIDATES]   DROP candidate (no match, no skips left)"));
        }
    }
    
    # Replace old candidates with new list
    state$active_candidates = new_candidates;
    debug_print(fmt("[UPDATE CANDIDATES] %d candidates still active", |new_candidates|));
}

# ---------------------------------------------------------------
# -        HELPER: CHECK IF COMMAND SETS OVERLAP                -
# ---------------------------------------------------------------
function commands_overlap(commands1: vector of count, commands2: vector of count): bool {
    for (i in commands1) {
        for (j in commands2) {
            if (commands1[i] == commands2[j])
                return T;
        }
    }
    return F;
}

# ---------------------------------------------------------------
# -        HELPER: COMMIT A MATCH (ASSIGN AND LOG)             -
# ---------------------------------------------------------------
function commit_match(conn_uid: string, cand: RuleCandidate, state: ConnectionState) {
    debug_print("");
    debug_print("=== COMMITTING MATCH ===");

    # Assign commands
    for (assign_idx_pos in cand$matched_command_indices) {
        local assign_cmd_idx = cand$matched_command_indices[assign_idx_pos];
        state$commands[assign_cmd_idx]$assigned = T;
        debug_print(fmt("Command %d marked as assigned", assign_cmd_idx));
    }

    # Get filename
    local filename = "";
    if (cand?$rule_filename_hashes) {
        filename = get_filename_from_match_filtered(state, cand$matched_command_indices, cand$rule_filename_hashes);
    } else {
        filename = get_filename_from_match(state, cand$matched_command_indices);
    }

    # Log the match
    local match_info: SMBMatchInfo;
    match_info$ts = network_time();
    match_info$uid = conn_uid;
    match_info$id = state$conn_id;
    match_info$filename = filename;
    match_info$application = cand$rule_application;
    match_info$description = cand$rule_description;

    Log::write(SMBCommandFingerprinting::MATCH_LOG, match_info);

    local rule_key = fmt("%s: %s", cand$rule_application, cand$rule_description);
    ++rule_match_counts[rule_key];

    debug_print(fmt("Application: %s", cand$rule_application));
    debug_print(fmt("Description: %s", cand$rule_description));
    debug_print(fmt("Signature length: %d", |cand$rule_signature|));
    debug_print(fmt("Commands matched: %d", |cand$matched_command_indices|));

    if (filename != "") {
        debug_print(fmt("Filename: %s", filename));
    }
    debug_print("========================");
    debug_print("");
}

# ---------------------------------------------------------------
# -        HELPER: CHECK FOR LONGER OVERLAPPING CANDIDATES     -
# ---------------------------------------------------------------
function has_longer_overlapping_candidates(cand: RuleCandidate, state: ConnectionState): bool {
    local cand_len = |cand$rule_signature|;

    for (other_idx in state$active_candidates) {
        local other = state$active_candidates[other_idx];
        local other_len = |other$rule_signature|;

        # Skip if not longer
        if (other_len <= cand_len)
            next;

        # Check if they overlap in commands
        if (commands_overlap(cand$matched_command_indices, other$matched_command_indices)) {
            debug_print(fmt("[PENDING] Found longer overlapping candidate: %s (len %d vs %d)",
                     other$rule_description, other_len, cand_len));
            return T;
        }
    }

    return F;
}

# ---------------------------------------------------------------
# -        COMMIT PENDING MATCHES (WHEN NO LONGER CANDIDATES)  -
# ---------------------------------------------------------------
function commit_pending_matches(conn_uid: string, cmd_index: count) {
    local state = connection_states[conn_uid];
    local remaining_pending: vector of PendingMatch = vector();

    # Define lookback window - commit if no activity for 10 commands
    local LOOKBACK_WINDOW = 10;

    for (pend_idx in state$pending_matches) {
        local pending = state$pending_matches[pend_idx];

        # Check if commands are still available
        local all_available = T;
        for (cmd_pos in pending$command_indices) {
            local cmd_idx = pending$command_indices[cmd_pos];
            if (state$commands[cmd_idx]$assigned) {
                all_available = F;
                debug_print(fmt("[PENDING COMMIT] Dropping pending match - command %d already assigned", cmd_idx));
                break;
            }
        }

        if (!all_available)
            next;

        # Check if there are still longer overlapping active candidates
        local still_has_longer = has_longer_overlapping_candidates(pending$candidate, state);

        # Check if enough commands have passed since pending
        local commands_passed = cmd_index - pending$pending_since_index;

        if (!still_has_longer || commands_passed >= LOOKBACK_WINDOW) {
            debug_print(fmt("[PENDING COMMIT] Committing pending match (len %d) - no longer candidates or timeout",
                     pending$signature_length));
            commit_match(conn_uid, pending$candidate, state);
        } else {
            debug_print(fmt("[PENDING COMMIT] Keeping pending match (len %d) - longer candidates still active",
                     pending$signature_length));
            remaining_pending[|remaining_pending|] = pending;
        }
    }

    state$pending_matches = remaining_pending;
}

# --------------------------------------------
# -        CHECK FOR RULE MATCHES            -
# --------------------------------------------
function check_for_matches(conn_uid: string, cmd_index: count) {
    local state = connection_states[conn_uid];
    local remaining_candidates: vector of RuleCandidate = vector();

    # Collect completed candidates sorted by signature length (longest first)
    local completed_candidates: vector of RuleCandidate = vector();

    for (cand_idx in state$active_candidates) {
        local cand = state$active_candidates[cand_idx];
        local sig = cand$rule_signature;

        if (cand$current_signature_position == |sig| - 1) {
            # Check if ANY command is already assigned
            local all_available = T;
            for (check_idx_pos in cand$matched_command_indices) {
                local check_cmd_idx = cand$matched_command_indices[check_idx_pos];
                if (state$commands[check_cmd_idx]$assigned) {
                    all_available = F;
                    debug_print(fmt("[MATCH CHECK] Candidate dropped - command %d already assigned", check_cmd_idx));
                    break;
                }
            }

            if (all_available) {
                # Add to completed list (will sort by length later)
                completed_candidates[|completed_candidates|] = clone_rule_candidate(cand);
                debug_print(fmt("[MATCH CHECK] Candidate completed: %s (len %d)",
                         cand$rule_description, |cand$rule_signature|));
            }
        } else {
            # Candidate still in progress
            remaining_candidates[|remaining_candidates|] = cand;
        }
    }

    # Process completed candidates: decide to commit immediately or make pending
    for (comp_idx in completed_candidates) {
        local comp_cand = completed_candidates[comp_idx];
        local sig_len = |comp_cand$rule_signature|;

        # Check if there are longer overlapping candidates that are still active
        local has_longer = has_longer_overlapping_candidates(comp_cand, state);

        if (has_longer) {
            # Create pending match - wait for longer candidates
            debug_print(fmt("[MATCH CHECK] Making pending: %s (len %d) - longer candidates exist",
                     comp_cand$rule_description, sig_len));

            local pending: PendingMatch;
            pending$candidate = clone_rule_candidate(comp_cand);
            pending$command_indices = vector();
            for (cmd_i in comp_cand$matched_command_indices) {
                pending$command_indices[|pending$command_indices|] = comp_cand$matched_command_indices[cmd_i];
            }
            pending$signature_length = sig_len;
            pending$pending_since_index = cmd_index;

            state$pending_matches[|state$pending_matches|] = pending;
        } else {
            # No longer candidates - commit immediately
            debug_print(fmt("[MATCH CHECK] Committing immediately: %s (len %d) - no longer candidates",
                     comp_cand$rule_description, sig_len));
            commit_match(conn_uid, comp_cand, state);

            # Remove invalidated remaining candidates
            local temp_remaining: vector of RuleCandidate = vector();
            for (rem_idx in remaining_candidates) {
                local rem_cand = remaining_candidates[rem_idx];
                local is_valid = T;

                for (val_pos in rem_cand$matched_command_indices) {
                    local val_cmd_idx = rem_cand$matched_command_indices[val_pos];
                    if (state$commands[val_cmd_idx]$assigned) {
                        is_valid = F;
                        debug_print(fmt("[MATCH CHECK] Dropping candidate after commit - command %d assigned", val_cmd_idx));
                        break;
                    }
                }

                if (is_valid) {
                    temp_remaining[|temp_remaining|] = rem_cand;
                }
            }
            remaining_candidates = temp_remaining;
        }
    }

    state$active_candidates = remaining_candidates;

    # Try to commit pending matches
    commit_pending_matches(conn_uid, cmd_index);
}

# -----------------------------------------------------------------------------
# -            CHECK POSSIBLE NEW RULE CANIDATES                              -
# -----------------------------------------------------------------------------
function process_new_command(conn_uid: string, cmd: SMBCommand, cid: conn_id) {
    if (conn_uid !in connection_states) {
        local new_state: ConnectionState;
        new_state$conn_id = cid;
        new_state$commands = vector();
        new_state$active_candidates = vector();
        new_state$pending_matches = vector();
        connection_states[conn_uid] = new_state;
    }

    local state = connection_states[conn_uid];
    
    local cmd_index = |state$commands|;
    state$commands[cmd_index] = cmd;
    
    debug_print("");
    debug_print("Processing new command:");
    debug_print(fmt("Command: %s", cmd$command));
    debug_print(fmt("Hash: %s", cmd$hash));
    debug_print(fmt("Is Compound: %s", cmd$is_compound ? "YES" : "NO"));
    if (cmd$is_compound && cmd?$individual_hashes) {
        debug_print(fmt("Individual Hashes: %s", join_string_vec(cmd$individual_hashes, ", ")));
    }
    debug_print(fmt("Assigned: %s", cmd$assigned ? "YES" : "NO"));
    if (cmd?$filename)
        debug_print(fmt("Filename: %s", cmd$filename));
    
    update_active_candidates(conn_uid, cmd_index);

    check_for_matches(conn_uid, cmd_index);

    check_for_new_candidates(conn_uid, cmd_index);
    
    debug_print(fmt("Active Candidates: %d", |state$active_candidates|));
    debug_print("");
}

# --------------------------------------------------------------------------------
# -                    PARSE SINGLE SMB COMMAND                                  -
# --------------------------------------------------------------------------------
function parse_smb_command_single(payload: string, is_orig: bool): SMBPacketInfo {
    local info: SMBPacketInfo;
    info$smb_version = "UNKNOWN";
    info$command = "UNKNOWN";
    info$command_code = 999;
    info$raw_data = payload;

    if (|payload| < 8)
        return info;
    
    local offset = 0;
    local cmd_offset: count;
    local cmd_bytes: string;
    local cmd_code: count;
    
    # NetBIOS Session Service Header
    if (payload[0:1] == "\x00") {
        offset = 4;
    }
    
    if (offset + 8 > |payload|)
        return info;
    
    # Only SMB2/3 Packets
    if (payload[offset:offset+1] == "\xfe" && payload[offset+1:offset+4] == "SMB") {
        info$smb_version = "SMB2/3";
        

        cmd_offset = offset + 12;
        if (cmd_offset + 1 <= |payload|) {
            cmd_bytes = payload[cmd_offset:cmd_offset+1];
            cmd_code = bytestring_to_count(cmd_bytes);
            info$command_code = cmd_code;
            
            if (cmd_code in smb2_commands) {
                info$command = smb2_commands[cmd_code];
            } else {
                info$command = fmt("UNKNOWN_SMB2_CMD_%d", cmd_code);
            }
        }

        # CREATE Command
        if (info$command == "CREATE") {
            if (is_orig) {
                local create_req = handle_create_request(info);
                if (create_req?$hash)
                    info$hash = create_req$hash;
                if (create_req?$FileName)
                    info$filename = create_req$FileName;
            } else {
                local create_resp = handle_create_response(info);
                if (create_resp?$hash)
                    info$hash = create_resp$hash;
            }
        }
        # CLOSE Command
        if (info$command == "CLOSE") {
            if (is_orig) {
                handle_close_request(info);
            } else {
                handle_close_response(info);
            }
        }
        # READ Command
        if (info$command == "READ") {
            if (is_orig) {
                local read_req = handle_read_request(info);
                if (read_req?$hash)
                    info$hash = read_req$hash;
            } else {
                handle_read_response(info);
            }
        }
        # WRITE Command
        if (info$command == "WRITE") {
            if (is_orig) {
                local write_req = handle_write_request(info);
                if (write_req?$hash)
                    info$hash = write_req$hash;
            } else {
                local write_resp = handle_write_response(info);
                if (write_resp?$hash)
                    info$hash = write_resp$hash;
            }
        }
        # QUERY_INFO Command 
        if (info$command == "QUERY_INFO") {
            if (is_orig) {
                local query_info_req = handle_query_info_request(info);
                if (query_info_req?$hash)
                    info$hash = query_info_req$hash;
            } else {
                local query_info_resp = handle_query_info_response(info);
                if (query_info_resp?$hash)
                    info$hash = query_info_resp$hash;
            }
        }
        # QUERY_DIRECTORY Command
        if (info$command == "QUERY_DIRECTORY") {
            if (is_orig) {
                local query_dir_req = handle_query_directory_request(info);
                if (query_dir_req?$hash)
                    info$hash = query_dir_req$hash;
            } else {
                handle_query_directory_response(info);
            }
        }
        # SET_INFO Command
        if (info$command == "SET_INFO") {
            if (is_orig) {
                local set_info_req = handle_set_info_request(info);
                if (set_info_req?$hash)
                    info$hash = set_info_req$hash;
                if (set_info_req?$FileName)
                    info$filename = set_info_req$FileName;
            } else {
                local set_info_resp = handle_set_info_response(info);
                if (set_info_resp?$hash)
                    info$hash = set_info_resp$hash;
            }
        }
    }

    return info;
}


# -----------------------------------------------------------------------------------
# -                PARSE COMPOUND COMMAND                                           -
# -----------------------------------------------------------------------------------
function parse_smb_command(payload: string, is_orig: bool): vector of SMBPacketInfo {
    local infos: vector of SMBPacketInfo = vector();

    local info = parse_smb_command_single(payload, is_orig);
    infos[0] = info;

    local offset = 0;
    if (payload[0:1] == "\x00") {
        offset = 4;
    }

    if (offset + 64 > |payload|) {
        return infos;
    }

    local next_command = parse_uint32_le(payload, offset + 20);


    if (next_command != 0) {
        # This is a compound command - mark the first command
        infos[0]$is_compound_part = T;
        infos[0]$compound_index = 0;

        local new_offset = offset + next_command;

        if (new_offset < |payload|) {
            local remaining_payload = "\x00\x00\x00\x00" + payload[new_offset:];
            local remaining_infos = parse_smb_command(remaining_payload, is_orig);

            # Mark all remaining commands as compound parts
            for (idx in remaining_infos) {
                remaining_infos[idx]$is_compound_part = T;
                remaining_infos[idx]$compound_index = |infos|;
                infos[|infos|] = remaining_infos[idx];
            }
        }

        debug_print(fmt("[COMPOUND DETECTION] Found compound command with %d parts", |infos|));
    }

    return infos;
}

# ---------------------------------------------
# -          CHECK IF SMB PACKET              -
# ---------------------------------------------
function is_smb_packet(payload: string): bool {
    if (|payload| < 8)
        return F;
    
    # NetBIOS Session Service with SMB2/3: \x00 + 3 bytes + \xfeSMB
    if (payload[0:1] == "\x00" && |payload| >= 8) {
        if (payload[4:5] == "\xfe" && payload[5:8] == "SMB")
            return T;
    }
    
    # SMB2/3 without NetBIOS: \xfeSMB
    if (payload[0:1] == "\xfe" && payload[1:4] == "SMB")
        return T;
    
    return F;
}

# Internal packet processing function
function process_tcp_packet_original(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
    # Only SMB-Ports (445 and 139)
    if (c$id$resp_p != 445/tcp && c$id$resp_p != 139/tcp)
        return;

    # Only with payload
    if (len == 0 || |payload| == 0)
        return;

    if (!is_smb_packet(payload))
        return;

    local parsed_infos = parse_smb_command(payload, is_orig);

    # Check if this is a compound command
    if (|parsed_infos| > 0 && parsed_infos[0]$is_compound_part) {
        debug_print(fmt("[COMPOUND PROCESSING] Processing compound with %d commands", |parsed_infos|));

        # Collect individual hashes and filenames
        local individual_hashes: vector of string = vector();
        local compound_commands: vector of string = vector();
        local compound_filename = "";

        for (comp_idx in parsed_infos) {
            local comp_info = parsed_infos[comp_idx];

            # Skip commands without hash
            if (!comp_info?$hash || comp_info$hash == "")
                next;

            individual_hashes[|individual_hashes|] = comp_info$hash;
            compound_commands[|compound_commands|] = comp_info$command;

            # Collect filename from any CREATE or SET_INFO in compound
            if (comp_info?$filename && compound_filename == "") {
                compound_filename = comp_info$filename;
            }
        }

        # Only process if we have valid hashes
        if (|individual_hashes| > 0) {
            # Calculate compound hash
            local compound_hash = create_compound_hash(individual_hashes);

            # Create single SMBCommand for the compound
            local comp_cmd: SMBCommand;
            comp_cmd$ts = network_time();
            comp_cmd$command = fmt("COMPOUND(%s)", join_string_vec(compound_commands, "+"));
            comp_cmd$hash = compound_hash;
            comp_cmd$is_compound = T;
            comp_cmd$individual_hashes = individual_hashes;

            if (compound_filename != "")
                comp_cmd$filename = compound_filename;

            comp_cmd$length = len;
            comp_cmd$is_response = !is_orig;
            comp_cmd$assigned = F;

            debug_print(fmt("[COMPOUND PROCESSING] Created compound: %s with hash %s", comp_cmd$command, compound_hash));

            process_new_command(c$uid, comp_cmd, c$id);
        }
    } else {
        # Individual command processing (original behavior)
        for (info_idx in parsed_infos) {
            local info = parsed_infos[info_idx];

            # Skip Commands without Hash
            if (!info?$hash || info$hash == "")
                next;

            local cmd: SMBCommand;
            cmd$ts = network_time();
            cmd$command = info$command;
            cmd$hash = info$hash;
            if (info?$filename)
                cmd$filename = info$filename;
            cmd$length = len;
            cmd$is_response = !is_orig;
            cmd$assigned = F;
            cmd$is_compound = F;

            process_new_command(c$uid, cmd, c$id);
        }
    }
}

# Simple completion detection - mark rules loaded when input ends
event Input::end_of_data(name: string, source: string) {
    if (name == "smb_rules_input") {
        rules_loaded = T;
        debug_print(fmt("Rule loading completed! Processing %d buffered packets...", |packet_buffer|));
        # Process buffered packets
        for (i in packet_buffer) {
            local pkt = packet_buffer[i];
            process_tcp_packet_original(pkt$c, pkt$is_orig, pkt$flags, pkt$seq, pkt$ack, pkt$len, pkt$payload);
        }
        packet_buffer = vector(); # Clear buffer
        debug_print("Buffered packets processed");
    }
}

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                     HASH-ONLY MODE PROCESSING                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
function process_tcp_packet_hash_only(c: connection, is_orig: bool, len: count, payload: string) {
    # Only SMB-Ports (445 and 139)
    if (c$id$resp_p != 445/tcp && c$id$resp_p != 139/tcp)
        return;

    # Only with payload
    if (len == 0 || |payload| == 0)
        return;

    if (!is_smb_packet(payload))
        return;

    local parsed_infos = parse_smb_command(payload, is_orig);

    # Increment packet counter
    ++packet_counter;

    # Check if this is a compound command
    if (|parsed_infos| > 0 && parsed_infos[0]$is_compound_part) {
        # Collect individual commands and hashes
        local individual_hashes: vector of string = vector();
        local compound_commands: vector of string = vector();

        for (comp_idx in parsed_infos) {
            local comp_info = parsed_infos[comp_idx];

            # Skip commands without hash
            if (!comp_info?$hash || comp_info$hash == "")
                next;

            individual_hashes[|individual_hashes|] = comp_info$hash;
            compound_commands[|compound_commands|] = comp_info$command;
        }

        # Only log if we have valid hashes
        if (|individual_hashes| > 0) {
            # Calculate compound hash
            local compound_hash = create_compound_hash(individual_hashes);

            # Build detail string: (CMD1:hash1, CMD2:hash2, ...)
            local details: vector of string = vector();
            for (i in compound_commands) {
                details[|details|] = fmt("%s:%s", compound_commands[i], individual_hashes[i]);
            }
            local detail_str = join_string_vec(details, ", ");

            # Create log entry
            local comp_hash_info: SMBHashInfo;
            comp_hash_info$packet_num = packet_counter;
            comp_hash_info$command = fmt("COMPOUND(%s)", join_string_vec(compound_commands, "+"));
            comp_hash_info$request_type = is_orig ? "Request" : "Response";
            comp_hash_info$hash = fmt("%s (%s)", compound_hash, detail_str);

            Log::write(SMBCommandFingerprinting::HASH_LOG, comp_hash_info);
        }
    } else {
        # Individual command processing
        for (info_idx in parsed_infos) {
            local info = parsed_infos[info_idx];

            # Skip commands without hash
            if (!info?$hash || info$hash == "")
                next;

            # Create log entry
            local ind_hash_info: SMBHashInfo;
            ind_hash_info$packet_num = packet_counter;
            ind_hash_info$command = info$command;
            ind_hash_info$request_type = is_orig ? "Request" : "Response";
            ind_hash_info$hash = info$hash;

            Log::write(SMBCommandFingerprinting::HASH_LOG, ind_hash_info);
        }
    }
}

# ------------------------------------------------------------------------------------------------------------------
# -                            HANDLE INCOMING TCP PACKET                                                          -
# ------------------------------------------------------------------------------------------------------------------
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
    # Hash-only mode: bypass all buffering and matching
    if (HASH_ONLY_MODE) {
        process_tcp_packet_hash_only(c, is_orig, len, payload);
        return;
    }

    # Buffer packets until rules are loaded
    if (!rules_loaded) {
        local buffered_pkt: BufferedPacket;
        buffered_pkt$c = c;
        buffered_pkt$is_orig = is_orig;
        buffered_pkt$flags = flags;
        buffered_pkt$seq = seq;
        buffered_pkt$ack = ack;
        buffered_pkt$len = len;
        buffered_pkt$payload = payload;

        packet_buffer[|packet_buffer|] = buffered_pkt;
        debug_print(fmt("Buffered packet %d (rules not loaded yet)", |packet_buffer|));
        return;
    }

    # Rules loaded, process immediately
    process_tcp_packet_original(c, is_orig, flags, seq, ack, len, payload);
}

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                        ZEEK END FUNCTION                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
event zeek_done() {
    # Commit all remaining pending matches before reporting statistics
    debug_print("");
    debug_print("=== Committing Remaining Pending Matches ===");
    for (conn_uid in connection_states) {
        local state = connection_states[conn_uid];
        if (|state$pending_matches| > 0) {
            debug_print(fmt("Connection %s has %d pending matches", conn_uid, |state$pending_matches|));
            for (pend_idx in state$pending_matches) {
                local pending = state$pending_matches[pend_idx];

                # Check if commands are still available
                local all_available = T;
                for (cmd_pos in pending$command_indices) {
                    local cmd_idx = pending$command_indices[cmd_pos];
                    if (state$commands[cmd_idx]$assigned) {
                        all_available = F;
                        break;
                    }
                }

                if (all_available) {
                    debug_print(fmt("[FINAL COMMIT] Committing pending match: %s (len %d)",
                             pending$candidate$rule_description, pending$signature_length));
                    commit_match(conn_uid, pending$candidate, state);
                } else {
                    debug_print(fmt("[FINAL COMMIT] Dropping pending match - commands already assigned"));
                }
            }
        }
    }
    debug_print("============================================");

    debug_print("");
    debug_print("=== SMB Matching Statistics ===");
    debug_print("");
    
    local total_reconstructed_commands = 0;
    
    if (|rule_match_counts| == 0) {
        debug_print("No rules were matched.");
    } else {
        for (rule_key in rule_match_counts) {
            debug_print(fmt("%s: %d matches", rule_key, rule_match_counts[rule_key]));
            total_reconstructed_commands += rule_match_counts[rule_key];
        }
    }
    
    debug_print("");
    debug_print(fmt("Total reconstructed commands: %d", total_reconstructed_commands));
    debug_print("===============================");

    organize_and_debug_rules();

}