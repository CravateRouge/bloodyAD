"""
[MS-ADTS] 3.1.1.3.1.9 Error Message Strings
[MS-ERREF] 2.2 Win32 Error Codes
"""

WIN32ERROR = {
    #   0x00000000: {"code": "ERROR_SUCCESS", "message": "The operation completed successfully."},
    0x00000001: {"code": "ERROR_INVALID_FUNCTION", "message": "Incorrect function."},
    0x00000002: {
        "code": "ERROR_FILE_NOT_FOUND",
        "message": "The system cannot find the file specified.",
    },
    0x00000003: {
        "code": "ERROR_PATH_NOT_FOUND",
        "message": "The system cannot find the path specified.",
    },
    0x00000004: {
        "code": "ERROR_TOO_MANY_OPEN_FILES",
        "message": "The system cannot open the file.",
    },
    0x00000005: {"code": "ERROR_ACCESS_DENIED", "message": "Access is denied."},
    0x00000006: {"code": "ERROR_INVALID_HANDLE", "message": "The handle is invalid."},
    0x00000007: {
        "code": "ERROR_ARENA_TRASHED",
        "message": "The storage control blocks were destroyed.",
    },
    0x00000008: {
        "code": "ERROR_NOT_ENOUGH_MEMORY",
        "message": "Not enough storage is available to process this command.",
    },
    0x00000009: {
        "code": "ERROR_INVALID_BLOCK",
        "message": "The storage control block address is invalid.",
    },
    0x0000000A: {
        "code": "ERROR_BAD_ENVIRONMENT",
        "message": "The environment is incorrect.",
    },
    0x0000000B: {
        "code": "ERROR_BAD_FORMAT",
        "message": "An attempt was made to load a program with an incorrect format.",
    },
    0x0000000C: {
        "code": "ERROR_INVALID_ACCESS",
        "message": "The access code is invalid.",
    },
    0x0000000D: {"code": "ERROR_INVALID_DATA", "message": "The data is invalid."},
    0x0000000E: {
        "code": "ERROR_OUTOFMEMORY",
        "message": "Not enough storage is available to complete this operation.",
    },
    0x0000000F: {
        "code": "ERROR_INVALID_DRIVE",
        "message": "The system cannot find the drive specified.",
    },
    0x00000010: {
        "code": "ERROR_CURRENT_DIRECTORY",
        "message": "The directory cannot be removed.",
    },
    0x00000011: {
        "code": "ERROR_NOT_SAME_DEVICE",
        "message": "The system cannot move the file to a different disk drive.",
    },
    0x00000012: {"code": "ERROR_NO_MORE_FILES", "message": "There are no more files."},
    0x00000013: {
        "code": "ERROR_WRITE_PROTECT",
        "message": "The media is write-protected.",
    },
    0x00000014: {
        "code": "ERROR_BAD_UNIT",
        "message": "The system cannot find the device specified.",
    },
    0x00000015: {"code": "ERROR_NOT_READY", "message": "The device is not ready."},
    0x00000016: {
        "code": "ERROR_BAD_COMMAND",
        "message": "The device does not recognize the command.",
    },
    0x00000017: {
        "code": "ERROR_CRC",
        "message": "Data error (cyclic redundancy check).",
    },
    0x00000018: {
        "code": "ERROR_BAD_LENGTH",
        "message": "The program issued a command but the command length is incorrect.",
    },
    0x00000019: {
        "code": "ERROR_SEEK",
        "message": "The drive cannot locate a specific area or track on the disk.",
    },
    0x0000001A: {
        "code": "ERROR_NOT_DOS_DISK",
        "message": "The specified disk cannot be accessed.",
    },
    0x0000001B: {
        "code": "ERROR_SECTOR_NOT_FOUND",
        "message": "The drive cannot find the sector requested.",
    },
    0x0000001C: {
        "code": "ERROR_OUT_OF_PAPER",
        "message": "The printer is out of paper.",
    },
    0x0000001D: {
        "code": "ERROR_WRITE_FAULT",
        "message": "The system cannot write to the specified device.",
    },
    0x0000001E: {
        "code": "ERROR_READ_FAULT",
        "message": "The system cannot read from the specified device.",
    },
    0x0000001F: {
        "code": "ERROR_GEN_FAILURE",
        "message": "A device attached to the system is not functioning.",
    },
    0x00000020: {
        "code": "ERROR_SHARING_VIOLATION",
        "message": (
            "The process cannot access the file because it is being used by another"
            " process."
        ),
    },
    0x00000021: {
        "code": "ERROR_LOCK_VIOLATION",
        "message": (
            "The process cannot access the file because another process has locked a"
            " portion of the file."
        ),
    },
    0x00000022: {
        "code": "ERROR_WRONG_DISK",
        "message": (
            "The wrong disk is in the drive. Insert %2 (Volume Serial Number: %3) into"
            " drive %1."
        ),
    },
    0x00000024: {
        "code": "ERROR_SHARING_BUFFER_EXCEEDED",
        "message": "Too many files opened for sharing.",
    },
    0x00000026: {"code": "ERROR_HANDLE_EOF", "message": "Reached the end of the file."},
    0x00000027: {"code": "ERROR_HANDLE_DISK_FULL", "message": "The disk is full."},
    0x00000032: {
        "code": "ERROR_NOT_SUPPORTED",
        "message": "The request is not supported.",
    },
    0x00000033: {
        "code": "ERROR_REM_NOT_LIST",
        "message": (
            "Windows cannot find the network path. Verify that the network path is"
            " correct and the destination computer is not busy or turned off. If"
            " Windows still cannot find the network path, contact your network"
            " administrator."
        ),
    },
    0x00000034: {
        "code": "ERROR_DUP_NAME",
        "message": (
            "You were not connected because a duplicate name exists on the network. Go"
            " to System in Control Panel to change the computer name, and then try"
            " again."
        ),
    },
    0x00000035: {
        "code": "ERROR_BAD_NETPATH",
        "message": "The network path was not found.",
    },
    0x00000036: {"code": "ERROR_NETWORK_BUSY", "message": "The network is busy."},
    0x00000037: {
        "code": "ERROR_DEV_NOT_EXIST",
        "message": "The specified network resource or device is no longer available.",
    },
    0x00000038: {
        "code": "ERROR_TOO_MANY_CMDS",
        "message": "The network BIOS command limit has been reached.",
    },
    0x00000039: {
        "code": "ERROR_ADAP_HDW_ERR",
        "message": "A network adapter hardware error occurred.",
    },
    0x0000003A: {
        "code": "ERROR_BAD_NET_RESP",
        "message": "The specified server cannot perform the requested operation.",
    },
    0x0000003B: {
        "code": "ERROR_UNEXP_NET_ERR",
        "message": "An unexpected network error occurred.",
    },
    0x0000003C: {
        "code": "ERROR_BAD_REM_ADAP",
        "message": "The remote adapter is not compatible.",
    },
    0x0000003D: {"code": "ERROR_PRINTQ_FULL", "message": "The print queue is full."},
    0x0000003E: {
        "code": "ERROR_NO_SPOOL_SPACE",
        "message": (
            "Space to store the file waiting to be printed is not available on the"
            " server."
        ),
    },
    0x0000003F: {
        "code": "ERROR_PRINT_CANCELLED",
        "message": "Your file waiting to be printed was deleted.",
    },
    0x00000040: {
        "code": "ERROR_NETNAME_DELETED",
        "message": "The specified network name is no longer available.",
    },
    0x00000041: {
        "code": "ERROR_NETWORK_ACCESS_DENIED",
        "message": "Network access is denied.",
    },
    0x00000042: {
        "code": "ERROR_BAD_DEV_TYPE",
        "message": "The network resource type is not correct.",
    },
    0x00000043: {
        "code": "ERROR_BAD_NET_NAME",
        "message": "The network name cannot be found.",
    },
    0x00000044: {
        "code": "ERROR_TOO_MANY_NAMES",
        "message": (
            "The name limit for the local computer network adapter card was exceeded."
        ),
    },
    0x00000045: {
        "code": "ERROR_TOO_MANY_SESS",
        "message": "The network BIOS session limit was exceeded.",
    },
    0x00000046: {
        "code": "ERROR_SHARING_PAUSED",
        "message": (
            "The remote server has been paused or is in the process of being started."
        ),
    },
    0x00000047: {
        "code": "ERROR_REQ_NOT_ACCEP",
        "message": (
            "No more connections can be made to this remote computer at this time"
            " because the computer has accepted the maximum number of connections."
        ),
    },
    0x00000048: {
        "code": "ERROR_REDIR_PAUSED",
        "message": "The specified printer or disk device has been paused.",
    },
    0x00000050: {"code": "ERROR_FILE_EXISTS", "message": "The file exists."},
    0x00000052: {
        "code": "ERROR_CANNOT_MAKE",
        "message": "The directory or file cannot be created.",
    },
    0x00000053: {"code": "ERROR_FAIL_I24", "message": "Fail on INT 24."},
    0x00000054: {
        "code": "ERROR_OUT_OF_STRUCTURES",
        "message": "Storage to process this request is not available.",
    },
    0x00000055: {
        "code": "ERROR_ALREADY_ASSIGNED",
        "message": "The local device name is already in use.",
    },
    0x00000056: {
        "code": "ERROR_INVALID_PASSWORD",
        "message": "The specified network password is not correct.",
    },
    0x00000057: {
        "code": "ERROR_INVALID_PARAMETER",
        "message": "The parameter is incorrect.",
    },
    0x00000058: {
        "code": "ERROR_NET_WRITE_FAULT",
        "message": "A write fault occurred on the network.",
    },
    0x00000059: {
        "code": "ERROR_NO_PROC_SLOTS",
        "message": "The system cannot start another process at this time.",
    },
    0x00000064: {
        "code": "ERROR_TOO_MANY_SEMAPHORES",
        "message": "Cannot create another system semaphore.",
    },
    0x00000065: {
        "code": "ERROR_EXCL_SEM_ALREADY_OWNED",
        "message": "The exclusive semaphore is owned by another process.",
    },
    0x00000066: {
        "code": "ERROR_SEM_IS_SET",
        "message": "The semaphore is set and cannot be closed.",
    },
    0x00000067: {
        "code": "ERROR_TOO_MANY_SEM_REQUESTS",
        "message": "The semaphore cannot be set again.",
    },
    0x00000068: {
        "code": "ERROR_INVALID_AT_INTERRUPT_TIME",
        "message": "Cannot request exclusive semaphores at interrupt time.",
    },
    0x00000069: {
        "code": "ERROR_SEM_OWNER_DIED",
        "message": "The previous ownership of this semaphore has ended.",
    },
    0x0000006A: {
        "code": "ERROR_SEM_USER_LIMIT",
        "message": "Insert the disk for drive %1.",
    },
    0x0000006B: {
        "code": "ERROR_DISK_CHANGE",
        "message": "The program stopped because an alternate disk was not inserted.",
    },
    0x0000006C: {
        "code": "ERROR_DRIVE_LOCKED",
        "message": "The disk is in use or locked by another process.",
    },
    0x0000006D: {"code": "ERROR_BROKEN_PIPE", "message": "The pipe has been ended."},
    0x0000006E: {
        "code": "ERROR_OPEN_FAILED",
        "message": "The system cannot open the device or file specified.",
    },
    0x0000006F: {
        "code": "ERROR_BUFFER_OVERFLOW",
        "message": "The file name is too long.",
    },
    0x00000070: {
        "code": "ERROR_DISK_FULL",
        "message": "There is not enough space on the disk.",
    },
    0x00000071: {
        "code": "ERROR_NO_MORE_SEARCH_HANDLES",
        "message": "No more internal file identifiers are available.",
    },
    0x00000072: {
        "code": "ERROR_INVALID_TARGET_HANDLE",
        "message": "The target internal file identifier is incorrect.",
    },
    0x00000075: {
        "code": "ERROR_INVALID_CATEGORY",
        "message": (
            "The Input Output Control (IOCTL) call made by the application program is"
            " not correct."
        ),
    },
    0x00000076: {
        "code": "ERROR_INVALID_VERIFY_SWITCH",
        "message": "The verify-on-write switch parameter value is not correct.",
    },
    0x00000077: {
        "code": "ERROR_BAD_DRIVER_LEVEL",
        "message": "The system does not support the command requested.",
    },
    0x00000078: {
        "code": "ERROR_CALL_NOT_IMPLEMENTED",
        "message": "This function is not supported on this system.",
    },
    0x00000079: {
        "code": "ERROR_SEM_TIMEOUT",
        "message": "The semaphore time-out period has expired.",
    },
    0x0000007A: {
        "code": "ERROR_INSUFFICIENT_BUFFER",
        "message": "The data area passed to a system call is too small.",
    },
    0x0000007B: {
        "code": "ERROR_INVALID_NAME",
        "message": (
            "The file name, directory name, or volume label syntax is incorrect."
        ),
    },
    0x0000007C: {
        "code": "ERROR_INVALID_LEVEL",
        "message": "The system call level is not correct.",
    },
    0x0000007D: {
        "code": "ERROR_NO_VOLUME_LABEL",
        "message": "The disk has no volume label.",
    },
    0x0000007E: {
        "code": "ERROR_MOD_NOT_FOUND",
        "message": "The specified module could not be found.",
    },
    0x0000007F: {
        "code": "ERROR_PROC_NOT_FOUND",
        "message": "The specified procedure could not be found.",
    },
    0x00000080: {
        "code": "ERROR_WAIT_NO_CHILDREN",
        "message": "There are no child processes to wait for.",
    },
    0x00000081: {
        "code": "ERROR_CHILD_NOT_COMPLETE",
        "message": "The %1 application cannot be run in Win32 mode.",
    },
    0x00000082: {
        "code": "ERROR_DIRECT_ACCESS_HANDLE",
        "message": (
            "Attempt to use a file handle to an open disk partition for an operation"
            " other than raw disk I/O."
        ),
    },
    0x00000083: {
        "code": "ERROR_NEGATIVE_SEEK",
        "message": (
            "An attempt was made to move the file pointer before the beginning of the"
            " file."
        ),
    },
    0x00000084: {
        "code": "ERROR_SEEK_ON_DEVICE",
        "message": "The file pointer cannot be set on the specified device or file.",
    },
    0x00000085: {
        "code": "ERROR_IS_JOIN_TARGET",
        "message": (
            "A JOIN or SUBST command cannot be used for a drive that contains"
            " previously joined drives."
        ),
    },
    0x00000086: {
        "code": "ERROR_IS_JOINED",
        "message": (
            "An attempt was made to use a JOIN or SUBST command on a drive that has"
            " already been joined."
        ),
    },
    0x00000087: {
        "code": "ERROR_IS_SUBSTED",
        "message": (
            "An attempt was made to use a JOIN or SUBST command on a drive that has"
            " already been substituted."
        ),
    },
    0x00000088: {
        "code": "ERROR_NOT_JOINED",
        "message": "The system tried to delete the JOIN of a drive that is not joined.",
    },
    0x00000089: {
        "code": "ERROR_NOT_SUBSTED",
        "message": (
            "The system tried to delete the substitution of a drive that is not"
            " substituted."
        ),
    },
    0x0000008A: {
        "code": "ERROR_JOIN_TO_JOIN",
        "message": "The system tried to join a drive to a directory on a joined drive.",
    },
    0x0000008B: {
        "code": "ERROR_SUBST_TO_SUBST",
        "message": (
            "The system tried to substitute a drive to a directory on a substituted"
            " drive."
        ),
    },
    0x0000008C: {
        "code": "ERROR_JOIN_TO_SUBST",
        "message": (
            "The system tried to join a drive to a directory on a substituted drive."
        ),
    },
    0x0000008D: {
        "code": "ERROR_SUBST_TO_JOIN",
        "message": (
            "The system tried to SUBST a drive to a directory on a joined drive."
        ),
    },
    0x0000008E: {
        "code": "ERROR_BUSY_DRIVE",
        "message": "The system cannot perform a JOIN or SUBST at this time.",
    },
    0x0000008F: {
        "code": "ERROR_SAME_DRIVE",
        "message": (
            "The system cannot join or substitute a drive to or for a directory on the"
            " same drive."
        ),
    },
    0x00000090: {
        "code": "ERROR_DIR_NOT_ROOT",
        "message": "The directory is not a subdirectory of the root directory.",
    },
    0x00000091: {
        "code": "ERROR_DIR_NOT_EMPTY",
        "message": "The directory is not empty.",
    },
    0x00000092: {
        "code": "ERROR_IS_SUBST_PATH",
        "message": "The path specified is being used in a substitute.",
    },
    0x00000093: {
        "code": "ERROR_IS_JOIN_PATH",
        "message": "Not enough resources are available to process this command.",
    },
    0x00000094: {
        "code": "ERROR_PATH_BUSY",
        "message": "The path specified cannot be used at this time.",
    },
    0x00000095: {
        "code": "ERROR_IS_SUBST_TARGET",
        "message": (
            "An attempt was made to join or substitute a drive for which a directory on"
            " the drive is the target of a previous substitute."
        ),
    },
    0x00000096: {
        "code": "ERROR_SYSTEM_TRACE",
        "message": (
            "System trace information was not specified in your CONFIG.SYS file, or"
            " tracing is disallowed."
        ),
    },
    0x00000097: {
        "code": "ERROR_INVALID_EVENT_COUNT",
        "message": (
            "The number of specified semaphore events for DosMuxSemWait is not correct."
        ),
    },
    0x00000098: {
        "code": "ERROR_TOO_MANY_MUXWAITERS",
        "message": (
            "DosMuxSemWait did not execute; too many semaphores are already set."
        ),
    },
    0x00000099: {
        "code": "ERROR_INVALID_LIST_FORMAT",
        "message": "The DosMuxSemWait list is not correct.",
    },
    0x0000009A: {
        "code": "ERROR_LABEL_TOO_LONG",
        "message": (
            "The volume label you entered exceeds the label character limit of the"
            " destination file system."
        ),
    },
    0x0000009B: {
        "code": "ERROR_TOO_MANY_TCBS",
        "message": "Cannot create another thread.",
    },
    0x0000009C: {
        "code": "ERROR_SIGNAL_REFUSED",
        "message": "The recipient process has refused the signal.",
    },
    0x0000009D: {
        "code": "ERROR_DISCARDED",
        "message": "The segment is already discarded and cannot be locked.",
    },
    0x0000009E: {
        "code": "ERROR_NOT_LOCKED",
        "message": "The segment is already unlocked.",
    },
    0x0000009F: {
        "code": "ERROR_BAD_THREADID_ADDR",
        "message": "The address for the thread ID is not correct.",
    },
    0x000000A0: {
        "code": "ERROR_BAD_ARGUMENTS",
        "message": "One or more arguments are not correct.",
    },
    0x000000A1: {
        "code": "ERROR_BAD_PATHNAME",
        "message": "The specified path is invalid.",
    },
    0x000000A2: {
        "code": "ERROR_SIGNAL_PENDING",
        "message": "A signal is already pending.",
    },
    0x000000A4: {
        "code": "ERROR_MAX_THRDS_REACHED",
        "message": "No more threads can be created in the system.",
    },
    0x000000A7: {
        "code": "ERROR_LOCK_FAILED",
        "message": "Unable to lock a region of a file.",
    },
    0x000000AA: {"code": "ERROR_BUSY", "message": "The requested resource is in use."},
    0x000000AD: {
        "code": "ERROR_CANCEL_VIOLATION",
        "message": "A lock request was not outstanding for the supplied cancel region.",
    },
    0x000000AE: {
        "code": "ERROR_ATOMIC_LOCKS_NOT_SUPPORTED",
        "message": "The file system does not support atomic changes to the lock type.",
    },
    0x000000B4: {
        "code": "ERROR_INVALID_SEGMENT_NUMBER",
        "message": "The system detected a segment number that was not correct.",
    },
    0x000000B6: {
        "code": "ERROR_INVALID_ORDINAL",
        "message": "The operating system cannot run %1.",
    },
    0x000000B7: {
        "code": "ERROR_ALREADY_EXISTS",
        "message": "Cannot create a file when that file already exists.",
    },
    0x000000BA: {
        "code": "ERROR_INVALID_FLAG_NUMBER",
        "message": "The flag passed is not correct.",
    },
    0x000000BB: {
        "code": "ERROR_SEM_NOT_FOUND",
        "message": "The specified system semaphore name was not found.",
    },
    0x000000BC: {
        "code": "ERROR_INVALID_STARTING_CODESEG",
        "message": "The operating system cannot run %1.",
    },
    0x000000BD: {
        "code": "ERROR_INVALID_STACKSEG",
        "message": "The operating system cannot run %1.",
    },
    0x000000BE: {
        "code": "ERROR_INVALID_MODULETYPE",
        "message": "The operating system cannot run %1.",
    },
    0x000000BF: {
        "code": "ERROR_INVALID_EXE_SIGNATURE",
        "message": "Cannot run %1 in Win32 mode.",
    },
    0x000000C0: {
        "code": "ERROR_EXE_MARKED_INVALID",
        "message": "The operating system cannot run %1.",
    },
    0x000000C1: {
        "code": "ERROR_BAD_EXE_FORMAT",
        "message": "%1 is not a valid Win32 application.",
    },
    0x000000C2: {
        "code": "ERROR_ITERATED_DATA_EXCEEDS_64k",
        "message": "The operating system cannot run %1.",
    },
    0x000000C3: {
        "code": "ERROR_INVALID_MINALLOCSIZE",
        "message": "The operating system cannot run %1.",
    },
    0x000000C4: {
        "code": "ERROR_DYNLINK_FROM_INVALID_RING",
        "message": "The operating system cannot run this application program.",
    },
    0x000000C5: {
        "code": "ERROR_IOPL_NOT_ENABLED",
        "message": (
            "The operating system is not presently configured to run this application."
        ),
    },
    0x000000C6: {
        "code": "ERROR_INVALID_SEGDPL",
        "message": "The operating system cannot run %1.",
    },
    0x000000C7: {
        "code": "ERROR_AUTODATASEG_EXCEEDS_64k",
        "message": "The operating system cannot run this application program.",
    },
    0x000000C8: {
        "code": "ERROR_RING2SEG_MUST_BE_MOVABLE",
        "message": "The code segment cannot be greater than or equal to 64 KB.",
    },
    0x000000C9: {
        "code": "ERROR_RELOC_CHAIN_XEEDS_SEGLIM",
        "message": "The operating system cannot run %1.",
    },
    0x000000CA: {
        "code": "ERROR_INFLOOP_IN_RELOC_CHAIN",
        "message": "The operating system cannot run %1.",
    },
    0x000000CB: {
        "code": "ERROR_ENVVAR_NOT_FOUND",
        "message": "The system could not find the environment option that was entered.",
    },
    0x000000CD: {
        "code": "ERROR_NO_SIGNAL_SENT",
        "message": "No process in the command subtree has a signal handler.",
    },
    0x000000CE: {
        "code": "ERROR_FILENAME_EXCED_RANGE",
        "message": "The file name or extension is too long.",
    },
    0x000000CF: {
        "code": "ERROR_RING2_STACK_IN_USE",
        "message": "The ring 2 stack is in use.",
    },
    0x000000D0: {
        "code": "ERROR_META_EXPANSION_TOO_LONG",
        "message": (
            "The asterisk (*) or question mark (?) global file name characters are"
            " entered incorrectly, or too many global file name characters are"
            " specified."
        ),
    },
    0x000000D1: {
        "code": "ERROR_INVALID_SIGNAL_NUMBER",
        "message": "The signal being posted is not correct.",
    },
    0x000000D2: {
        "code": "ERROR_THREAD_1_INACTIVE",
        "message": "The signal handler cannot be set.",
    },
    0x000000D4: {
        "code": "ERROR_LOCKED",
        "message": "The segment is locked and cannot be reallocated.",
    },
    0x000000D6: {
        "code": "ERROR_TOO_MANY_MODULES",
        "message": (
            "Too many dynamic-link modules are attached to this program or dynamic-link"
            " module."
        ),
    },
    0x000000D7: {
        "code": "ERROR_NESTING_NOT_ALLOWED",
        "message": "Cannot nest calls to LoadModule.",
    },
    0x000000D8: {
        "code": "ERROR_EXE_MACHINE_TYPE_MISMATCH",
        "message": (
            "This version of %1 is not compatible with the version of Windows you're"
            " running. Check your computer's system information to see whether you need"
            " an x86 (32-bit) or x64 (64-bit) version of the program, and then contact"
            " the software publisher."
        ),
    },
    0x000000D9: {
        "code": "ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY",
        "message": "The image file %1 is signed, unable to modify.",
    },
    0x000000DA: {
        "code": "ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY",
        "message": "The image file %1 is strong signed, unable to modify.",
    },
    0x000000DC: {
        "code": "ERROR_FILE_CHECKED_OUT",
        "message": "This file is checked out or locked for editing by another user.",
    },
    0x000000DD: {
        "code": "ERROR_CHECKOUT_REQUIRED",
        "message": "The file must be checked out before saving changes.",
    },
    0x000000DE: {
        "code": "ERROR_BAD_FILE_TYPE",
        "message": "The file type being saved or retrieved has been blocked.",
    },
    0x000000DF: {
        "code": "ERROR_FILE_TOO_LARGE",
        "message": "The file size exceeds the limit allowed and cannot be saved.",
    },
    0x000000E0: {
        "code": "ERROR_FORMS_AUTH_REQUIRED",
        "message": (
            "Access denied. Before opening files in this location, you must first"
            " browse to the website and select the option to sign in automatically."
        ),
    },
    0x000000E1: {
        "code": "ERROR_VIRUS_INFECTED",
        "message": (
            "Operation did not complete successfully because the file contains a virus."
        ),
    },
    0x000000E2: {
        "code": "ERROR_VIRUS_DELETED",
        "message": (
            "This file contains a virus and cannot be opened. Due to the nature of this"
            " virus, the file has been removed from this location."
        ),
    },
    0x000000E5: {"code": "ERROR_PIPE_LOCAL", "message": "The pipe is local."},
    0x000000E6: {"code": "ERROR_BAD_PIPE", "message": "The pipe state is invalid."},
    0x000000E7: {"code": "ERROR_PIPE_BUSY", "message": "All pipe instances are busy."},
    0x000000E8: {"code": "ERROR_NO_DATA", "message": "The pipe is being closed."},
    0x000000E9: {
        "code": "ERROR_PIPE_NOT_CONNECTED",
        "message": "No process is on the other end of the pipe.",
    },
    0x000000EA: {"code": "ERROR_MORE_DATA", "message": "More data is available."},
    0x000000F0: {
        "code": "ERROR_VC_DISCONNECTED",
        "message": "The session was canceled.",
    },
    0x000000FE: {
        "code": "ERROR_INVALID_EA_NAME",
        "message": "The specified extended attribute name was invalid.",
    },
    0x000000FF: {
        "code": "ERROR_EA_LIST_INCONSISTENT",
        "message": "The extended attributes are inconsistent.",
    },
    0x00000102: {"code": "WAIT_TIMEOUT", "message": "The wait operation timed out."},
    0x00000103: {
        "code": "ERROR_NO_MORE_ITEMS",
        "message": "No more data is available.",
    },
    0x0000010A: {
        "code": "ERROR_CANNOT_COPY",
        "message": "The copy functions cannot be used.",
    },
    0x0000010B: {
        "code": "ERROR_DIRECTORY",
        "message": "The directory name is invalid.",
    },
    0x00000113: {
        "code": "ERROR_EAS_DIDNT_FIT",
        "message": "The extended attributes did not fit in the buffer.",
    },
    0x00000114: {
        "code": "ERROR_EA_FILE_CORRUPT",
        "message": "The extended attribute file on the mounted file system is corrupt.",
    },
    0x00000115: {
        "code": "ERROR_EA_TABLE_FULL",
        "message": "The extended attribute table file is full.",
    },
    0x00000116: {
        "code": "ERROR_INVALID_EA_HANDLE",
        "message": "The specified extended attribute handle is invalid.",
    },
    0x0000011A: {
        "code": "ERROR_EAS_NOT_SUPPORTED",
        "message": "The mounted file system does not support extended attributes.",
    },
    0x00000120: {
        "code": "ERROR_NOT_OWNER",
        "message": "Attempt to release mutex not owned by caller.",
    },
    0x0000012A: {
        "code": "ERROR_TOO_MANY_POSTS",
        "message": "Too many posts were made to a semaphore.",
    },
    0x0000012B: {
        "code": "ERROR_PARTIAL_COPY",
        "message": (
            "Only part of a ReadProcessMemory or WriteProcessMemory request was"
            " completed."
        ),
    },
    0x0000012C: {
        "code": "ERROR_OPLOCK_NOT_GRANTED",
        "message": "The oplock request is denied.",
    },
    0x0000012D: {
        "code": "ERROR_INVALID_OPLOCK_PROTOCOL",
        "message": "An invalid oplock acknowledgment was received by the system.",
    },
    0x0000012E: {
        "code": "ERROR_DISK_TOO_FRAGMENTED",
        "message": "The volume is too fragmented to complete this operation.",
    },
    0x0000012F: {
        "code": "ERROR_DELETE_PENDING",
        "message": (
            "The file cannot be opened because it is in the process of being deleted."
        ),
    },
    0x0000013D: {
        "code": "ERROR_MR_MID_NOT_FOUND",
        "message": (
            "The system cannot find message text for message number 0x%1 in the message"
            " file for %2."
        ),
    },
    0x0000013E: {
        "code": "ERROR_SCOPE_NOT_FOUND",
        "message": "The scope specified was not found.",
    },
    0x0000015E: {
        "code": "ERROR_FAIL_NOACTION_REBOOT",
        "message": "No action was taken because a system reboot is required.",
    },
    0x0000015F: {
        "code": "ERROR_FAIL_SHUTDOWN",
        "message": "The shutdown operation failed.",
    },
    0x00000160: {
        "code": "ERROR_FAIL_RESTART",
        "message": "The restart operation failed.",
    },
    0x00000161: {
        "code": "ERROR_MAX_SESSIONS_REACHED",
        "message": "The maximum number of sessions has been reached.",
    },
    0x00000190: {
        "code": "ERROR_THREAD_MODE_ALREADY_BACKGROUND",
        "message": "The thread is already in background processing mode.",
    },
    0x00000191: {
        "code": "ERROR_THREAD_MODE_NOT_BACKGROUND",
        "message": "The thread is not in background processing mode.",
    },
    0x00000192: {
        "code": "ERROR_PROCESS_MODE_ALREADY_BACKGROUND",
        "message": "The process is already in background processing mode.",
    },
    0x00000193: {
        "code": "ERROR_PROCESS_MODE_NOT_BACKGROUND",
        "message": "The process is not in background processing mode.",
    },
    0x000001E7: {
        "code": "ERROR_INVALID_ADDRESS",
        "message": "Attempt to access invalid address.",
    },
    0x000001F4: {
        "code": "ERROR_USER_PROFILE_LOAD",
        "message": "User profile cannot be loaded.",
    },
    0x00000216: {
        "code": "ERROR_ARITHMETIC_OVERFLOW",
        "message": "Arithmetic result exceeded 32 bits.",
    },
    0x00000217: {
        "code": "ERROR_PIPE_CONNECTED",
        "message": "There is a process on the other end of the pipe.",
    },
    0x00000218: {
        "code": "ERROR_PIPE_LISTENING",
        "message": "Waiting for a process to open the other end of the pipe.",
    },
    0x00000219: {
        "code": "ERROR_VERIFIER_STOP",
        "message": "Application verifier has found an error in the current process.",
    },
    0x0000021A: {
        "code": "ERROR_ABIOS_ERROR",
        "message": "An error occurred in the ABIOS subsystem.",
    },
    0x0000021B: {
        "code": "ERROR_WX86_WARNING",
        "message": "A warning occurred in the WX86 subsystem.",
    },
    0x0000021C: {
        "code": "ERROR_WX86_ERROR",
        "message": "An error occurred in the WX86 subsystem.",
    },
    0x0000021D: {
        "code": "ERROR_TIMER_NOT_CANCELED",
        "message": (
            "An attempt was made to cancel or set a timer that has an associated"
            " asynchronous procedure call (APC) and the subject thread is not the"
            " thread that originally set the timer with an associated APC routine."
        ),
    },
    0x0000021E: {"code": "ERROR_UNWIND", "message": "Unwind exception code."},
    0x0000021F: {
        "code": "ERROR_BAD_STACK",
        "message": (
            "An invalid or unaligned stack was encountered during an unwind operation."
        ),
    },
    0x00000220: {
        "code": "ERROR_INVALID_UNWIND_TARGET",
        "message": (
            "An invalid unwind target was encountered during an unwind operation."
        ),
    },
    0x00000221: {
        "code": "ERROR_INVALID_PORT_ATTRIBUTES",
        "message": (
            "Invalid object attributes specified to NtCreatePort or invalid port"
            " attributes specified to NtConnectPort."
        ),
    },
    0x00000222: {
        "code": "ERROR_PORT_MESSAGE_TOO_LONG",
        "message": (
            "Length of message passed to NtRequestPort or NtRequestWaitReplyPort was"
            " longer than the maximum message allowed by the port."
        ),
    },
    0x00000223: {
        "code": "ERROR_INVALID_QUOTA_LOWER",
        "message": (
            "An attempt was made to lower a quota limit below the current usage."
        ),
    },
    0x00000224: {
        "code": "ERROR_DEVICE_ALREADY_ATTACHED",
        "message": (
            "An attempt was made to attach to a device that was already attached to"
            " another device."
        ),
    },
    0x00000225: {
        "code": "ERROR_INSTRUCTION_MISALIGNMENT",
        "message": (
            "An attempt was made to execute an instruction at an unaligned address, and"
            " the host system does not support unaligned instruction references."
        ),
    },
    0x00000226: {
        "code": "ERROR_PROFILING_NOT_STARTED",
        "message": "Profiling not started.",
    },
    0x00000227: {
        "code": "ERROR_PROFILING_NOT_STOPPED",
        "message": "Profiling not stopped.",
    },
    0x00000228: {
        "code": "ERROR_COULD_NOT_INTERPRET",
        "message": "The passed ACL did not contain the minimum required information.",
    },
    0x00000229: {
        "code": "ERROR_PROFILING_AT_LIMIT",
        "message": (
            "The number of active profiling objects is at the maximum and no more can"
            " be started."
        ),
    },
    0x0000022A: {
        "code": "ERROR_CANT_WAIT",
        "message": (
            "Used to indicate that an operation cannot continue without blocking for"
            " I/O."
        ),
    },
    0x0000022B: {
        "code": "ERROR_CANT_TERMINATE_SELF",
        "message": (
            "Indicates that a thread attempted to terminate itself by default (called"
            " NtTerminateThread with NULL) and it was the last thread in the current"
            " process."
        ),
    },
    0x0000022C: {
        "code": "ERROR_UNEXPECTED_MM_CREATE_ERR",
        "message": (
            "If an MM error is returned that is not defined in the standard FsRtl"
            " filter, it is converted to one of the following errors that is guaranteed"
            " to be in the filter. In this case, information is lost; however, the"
            " filter correctly handles the exception."
        ),
    },
    0x0000022D: {
        "code": "ERROR_UNEXPECTED_MM_MAP_ERROR",
        "message": (
            "If an MM error is returned that is not defined in the standard FsRtl"
            " filter, it is converted to one of the following errors that is guaranteed"
            " to be in the filter. In this case, information is lost; however, the"
            " filter correctly handles the exception."
        ),
    },
    0x0000022E: {
        "code": "ERROR_UNEXPECTED_MM_EXTEND_ERR",
        "message": (
            "If an MM error is returned that is not defined in the standard FsRtl"
            " filter, it is converted to one of the following errors that is guaranteed"
            " to be in the filter. In this case, information is lost; however, the"
            " filter correctly handles the exception."
        ),
    },
    0x0000022F: {
        "code": "ERROR_BAD_FUNCTION_TABLE",
        "message": (
            "A malformed function table was encountered during an unwind operation."
        ),
    },
    0x00000230: {
        "code": "ERROR_NO_GUID_TRANSLATION",
        "message": (
            "Indicates that an attempt was made to assign protection to a file system"
            " file or directory and one of the SIDs in the security descriptor could"
            " not be translated into a GUID that could be stored by the file system."
            " This causes the protection attempt to fail, which might cause a file"
            " creation attempt to fail."
        ),
    },
    0x00000231: {
        "code": "ERROR_INVALID_LDT_SIZE",
        "message": (
            "Indicates that an attempt was made to grow a local domain table (LDT) by"
            " setting its size, or that the size was not an even number of selectors."
        ),
    },
    0x00000233: {
        "code": "ERROR_INVALID_LDT_OFFSET",
        "message": (
            "Indicates that the starting value for the LDT information was not an"
            " integral multiple of the selector size."
        ),
    },
    0x00000234: {
        "code": "ERROR_INVALID_LDT_DESCRIPTOR",
        "message": (
            "Indicates that the user supplied an invalid descriptor when trying to set"
            " up LDT descriptors."
        ),
    },
    0x00000235: {
        "code": "ERROR_TOO_MANY_THREADS",
        "message": (
            "Indicates a process has too many threads to perform the requested action."
            " For example, assignment of a primary token can be performed only when a"
            " process has zero or one threads."
        ),
    },
    0x00000236: {
        "code": "ERROR_THREAD_NOT_IN_PROCESS",
        "message": (
            "An attempt was made to operate on a thread within a specific process, but"
            " the thread specified is not in the process specified."
        ),
    },
    0x00000237: {
        "code": "ERROR_PAGEFILE_QUOTA_EXCEEDED",
        "message": "Page file quota was exceeded.",
    },
    0x00000238: {
        "code": "ERROR_LOGON_SERVER_CONFLICT",
        "message": (
            "The Netlogon service cannot start because another Netlogon service running"
            " in the domain conflicts with the specified role."
        ),
    },
    0x00000239: {
        "code": "ERROR_SYNCHRONIZATION_REQUIRED",
        "message": (
            "On applicable Windows Server releases, the Security Accounts Manager (SAM)"
            " database is significantly out of synchronization with the copy on the"
            " domain controller. A complete synchronization is required."
        ),
    },
    0x0000023A: {
        "code": "ERROR_NET_OPEN_FAILED",
        "message": (
            "The NtCreateFile API failed. This error should never be returned to an"
            " application, it is a place holder for the Windows LAN Manager Redirector"
            " to use in its internal error mapping routines."
        ),
    },
    0x0000023B: {
        "code": "ERROR_IO_PRIVILEGE_FAILED",
        "message": (
            "{Privilege Failed} The I/O permissions for the process could not be"
            " changed."
        ),
    },
    0x0000023C: {
        "code": "ERROR_CONTROL_C_EXIT",
        "message": (
            "{Application Exit by CTRL+C} The application terminated as a result of a"
            " CTRL+C."
        ),
    },
    0x0000023D: {
        "code": "ERROR_MISSING_SYSTEMFILE",
        "message": (
            "{Missing System File} The required system file %hs is bad or missing."
        ),
    },
    0x0000023E: {
        "code": "ERROR_UNHANDLED_EXCEPTION",
        "message": (
            "{Application Error} The exception %s (0x%08lx) occurred in the application"
            " at location 0x%08lx."
        ),
    },
    0x0000023F: {
        "code": "ERROR_APP_INIT_FAILURE",
        "message": (
            "{Application Error} The application failed to initialize properly (0x%lx)."
            " Click OK to terminate the application."
        ),
    },
    0x00000240: {
        "code": "ERROR_PAGEFILE_CREATE_FAILED",
        "message": (
            "{Unable to Create Paging File} The creation of the paging file %hs failed"
            " (%lx). The requested size was %ld."
        ),
    },
    0x00000241: {
        "code": "ERROR_INVALID_IMAGE_HASH",
        "message": (
            "The hash for the image cannot be found in the system catalogs. The image"
            " is likely corrupt or the victim of tampering."
        ),
    },
    0x00000242: {
        "code": "ERROR_NO_PAGEFILE",
        "message": (
            "{No Paging File Specified} No paging file was specified in the system"
            " configuration."
        ),
    },
    0x00000243: {
        "code": "ERROR_ILLEGAL_FLOAT_CONTEXT",
        "message": (
            "{EXCEPTION} A real-mode application issued a floating-point instruction,"
            " and floating-point hardware is not present."
        ),
    },
    0x00000244: {
        "code": "ERROR_NO_EVENT_PAIR",
        "message": (
            "An event pair synchronization operation was performed using the"
            " thread-specific client/server event pair object, but no event pair object"
            " was associated with the thread."
        ),
    },
    0x00000245: {
        "code": "ERROR_DOMAIN_CTRLR_CONFIG_ERROR",
        "message": "A domain server has an incorrect configuration.",
    },
    0x00000246: {
        "code": "ERROR_ILLEGAL_CHARACTER",
        "message": (
            "An illegal character was encountered. For a multibyte character set, this"
            " includes a lead byte without a succeeding trail byte. For the Unicode"
            " character set, this includes the characters 0xFFFF and 0xFFFE."
        ),
    },
    0x00000247: {
        "code": "ERROR_UNDEFINED_CHARACTER",
        "message": (
            "The Unicode character is not defined in the Unicode character set"
            " installed on the system."
        ),
    },
    0x00000248: {
        "code": "ERROR_FLOPPY_VOLUME",
        "message": "The paging file cannot be created on a floppy disk.",
    },
    0x00000249: {
        "code": "ERROR_BIOS_FAILED_TO_CONNECT_INTERRUPT",
        "message": (
            "The system bios failed to connect a system interrupt to the device or bus"
            " for which the device is connected."
        ),
    },
    0x0000024A: {
        "code": "ERROR_BACKUP_CONTROLLER",
        "message": (
            "This operation is only allowed for the primary domain controller (PDC) of"
            " the domain."
        ),
    },
    0x0000024B: {
        "code": "ERROR_MUTANT_LIMIT_EXCEEDED",
        "message": (
            "An attempt was made to acquire a mutant such that its maximum count would"
            " have been exceeded."
        ),
    },
    0x0000024C: {
        "code": "ERROR_FS_DRIVER_REQUIRED",
        "message": (
            "A volume has been accessed for which a file system driver is required that"
            " has not yet been loaded."
        ),
    },
    0x0000024D: {
        "code": "ERROR_CANNOT_LOAD_REGISTRY_FILE",
        "message": (
            "{Registry File Failure} The registry cannot load the hive (file): %hs or"
            " its log or alternate. It is corrupt, absent, or not writable."
        ),
    },
    0x0000024E: {
        "code": "ERROR_DEBUG_ATTACH_FAILED",
        "message": (
            "{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred"
            " while processing a DebugActiveProcess API request. Choosing OK will"
            " terminate the process, and choosing Cancel will ignore the error."
        ),
    },
    0x0000024F: {
        "code": "ERROR_SYSTEM_PROCESS_TERMINATED",
        "message": (
            "{Fatal System Error} The %hs system process terminated unexpectedly with a"
            " status of 0x%08x (0x%08x 0x%08x). The system has been shut down."
        ),
    },
    0x00000250: {
        "code": "ERROR_DATA_NOT_ACCEPTED",
        "message": (
            "{Data Not Accepted} The transport driver interface (TDI) client could not"
            " handle the data received during an indication."
        ),
    },
    0x00000251: {
        "code": "ERROR_VDM_HARD_ERROR",
        "message": "The NT Virtual DOS Machine (NTVDM) encountered a hard error.",
    },
    0x00000252: {
        "code": "ERROR_DRIVER_CANCEL_TIMEOUT",
        "message": (
            "{Cancel Timeout} The driver %hs failed to complete a canceled I/O request"
            " in the allotted time."
        ),
    },
    0x00000253: {
        "code": "ERROR_REPLY_MESSAGE_MISMATCH",
        "message": (
            "{Reply Message Mismatch} An attempt was made to reply to a local procedure"
            " call (LPC) message, but the thread specified by the client ID in the"
            " message was not waiting on that message."
        ),
    },
    0x00000254: {
        "code": "ERROR_LOST_WRITEBEHIND_DATA",
        "message": (
            "{Delayed Write Failed} Windows was unable to save all the data for the"
            " file %hs. The data has been lost. This error might be caused by a failure"
            " of your computer hardware or network connection. Try to save this file"
            " elsewhere."
        ),
    },
    0x00000255: {
        "code": "ERROR_CLIENT_SERVER_PARAMETERS_INVALID",
        "message": (
            "The parameters passed to the server in the client/server shared memory"
            " window were invalid. Too much data might have been put in the shared"
            " memory window."
        ),
    },
    0x00000256: {
        "code": "ERROR_NOT_TINY_STREAM",
        "message": "The stream is not a tiny stream.",
    },
    0x00000257: {
        "code": "ERROR_STACK_OVERFLOW_READ",
        "message": "The request must be handled by the stack overflow code.",
    },
    0x00000258: {
        "code": "ERROR_CONVERT_TO_LARGE",
        "message": (
            "Internal OFS status codes indicating how an allocation operation is"
            " handled. Either it is retried after the containing onode is moved or the"
            " extent stream is converted to a large stream."
        ),
    },
    0x00000259: {
        "code": "ERROR_FOUND_OUT_OF_SCOPE",
        "message": (
            "The attempt to find the object found an object matching by ID on the"
            " volume but it is out of the scope of the handle used for the operation."
        ),
    },
    0x0000025A: {
        "code": "ERROR_ALLOCATE_BUCKET",
        "message": "The bucket array must be grown. Retry transaction after doing so.",
    },
    0x0000025B: {
        "code": "ERROR_MARSHALL_OVERFLOW",
        "message": "The user/kernel marshaling buffer has overflowed.",
    },
    0x0000025C: {
        "code": "ERROR_INVALID_VARIANT",
        "message": "The supplied variant structure contains invalid data.",
    },
    0x0000025D: {
        "code": "ERROR_BAD_COMPRESSION_BUFFER",
        "message": "The specified buffer contains ill-formed data.",
    },
    0x0000025E: {
        "code": "ERROR_AUDIT_FAILED",
        "message": "{Audit Failed} An attempt to generate a security audit failed.",
    },
    0x0000025F: {
        "code": "ERROR_TIMER_RESOLUTION_NOT_SET",
        "message": (
            "The timer resolution was not previously set by the current process."
        ),
    },
    0x00000260: {
        "code": "ERROR_INSUFFICIENT_LOGON_INFO",
        "message": "There is insufficient account information to log you on.",
    },
    0x00000261: {
        "code": "ERROR_BAD_DLL_ENTRYPOINT",
        "message": (
            "{Invalid DLL Entrypoint} The dynamic link library %hs is not written"
            " correctly. The stack pointer has been left in an inconsistent state. The"
            " entry point should be declared as WINAPI or STDCALL. Select YES to fail"
            " the DLL load. Select NO to continue execution. Selecting NO can cause the"
            " application to operate incorrectly."
        ),
    },
    0x00000262: {
        "code": "ERROR_BAD_SERVICE_ENTRYPOINT",
        "message": (
            "{Invalid Service Callback Entrypoint} The %hs service is not written"
            " correctly. The stack pointer has been left in an inconsistent state. The"
            " callback entry point should be declared as WINAPI or STDCALL. Selecting"
            " OK will cause the service to continue operation. However, the service"
            " process might operate incorrectly."
        ),
    },
    0x00000263: {
        "code": "ERROR_IP_ADDRESS_CONFLICT1",
        "message": (
            "There is an IP address conflict with another system on the network."
        ),
    },
    0x00000264: {
        "code": "ERROR_IP_ADDRESS_CONFLICT2",
        "message": (
            "There is an IP address conflict with another system on the network."
        ),
    },
    0x00000265: {
        "code": "ERROR_REGISTRY_QUOTA_LIMIT",
        "message": (
            "{Low On Registry Space} The system has reached the maximum size allowed"
            " for the system part of the registry. Additional storage requests will be"
            " ignored."
        ),
    },
    0x00000266: {
        "code": "ERROR_NO_CALLBACK_ACTIVE",
        "message": (
            "A callback return system service cannot be executed when no callback is"
            " active."
        ),
    },
    0x00000267: {
        "code": "ERROR_PWD_TOO_SHORT",
        "message": (
            "The password provided is too short to meet the policy of your user"
            " account. Choose a longer password."
        ),
    },
    0x00000268: {
        "code": "ERROR_PWD_TOO_RECENT",
        "message": (
            "The policy of your user account does not allow you to change passwords too"
            " frequently. This is done to prevent users from changing back to a"
            " familiar, but potentially discovered, password. If you feel your password"
            " has been compromised, contact your administrator immediately to have a"
            " new one assigned."
        ),
    },
    0x00000269: {
        "code": "ERROR_PWD_HISTORY_CONFLICT",
        "message": (
            "You have attempted to change your password to one that you have used in"
            " the past. The policy of your user account does not allow this. Select a"
            " password that you have not previously used."
        ),
    },
    0x0000026A: {
        "code": "ERROR_UNSUPPORTED_COMPRESSION",
        "message": "The specified compression format is unsupported.",
    },
    0x0000026B: {
        "code": "ERROR_INVALID_HW_PROFILE",
        "message": "The specified hardware profile configuration is invalid.",
    },
    0x0000026C: {
        "code": "ERROR_INVALID_PLUGPLAY_DEVICE_PATH",
        "message": "The specified Plug and Play registry device path is invalid.",
    },
    0x0000026D: {
        "code": "ERROR_QUOTA_LIST_INCONSISTENT",
        "message": (
            "The specified quota list is internally inconsistent with its descriptor."
        ),
    },
    0x0000026E: {
        "code": "ERROR_EVALUATION_EXPIRATION",
        "message": (
            "{Windows Evaluation Notification} The evaluation period for this"
            " installation of Windows has expired. This system will shut down in 1"
            " hour. To restore access to this installation of Windows, upgrade this"
            " installation using a licensed distribution of this product."
        ),
    },
    0x0000026F: {
        "code": "ERROR_ILLEGAL_DLL_RELOCATION",
        "message": (
            "{Illegal System DLL Relocation} The system DLL %hs was relocated in"
            " memory. The application will not run properly. The relocation occurred"
            " because the DLL %hs occupied an address range reserved for Windows system"
            " DLLs. The vendor supplying the DLL should be contacted for a new DLL."
        ),
    },
    0x00000270: {
        "code": "ERROR_DLL_INIT_FAILED_LOGOFF",
        "message": (
            "{DLL Initialization Failed} The application failed to initialize because"
            " the window station is shutting down."
        ),
    },
    0x00000271: {
        "code": "ERROR_VALIDATE_CONTINUE",
        "message": "The validation process needs to continue on to the next step.",
    },
    0x00000272: {
        "code": "ERROR_NO_MORE_MATCHES",
        "message": "There are no more matches for the current index enumeration.",
    },
    0x00000273: {
        "code": "ERROR_RANGE_LIST_CONFLICT",
        "message": (
            "The range could not be added to the range list because of a conflict."
        ),
    },
    0x00000274: {
        "code": "ERROR_SERVER_SID_MISMATCH",
        "message": (
            "The server process is running under a SID different than that required by"
            " the client."
        ),
    },
    0x00000275: {
        "code": "ERROR_CANT_ENABLE_DENY_ONLY",
        "message": "A group marked use for deny only cannot be enabled.",
    },
    0x00000276: {
        "code": "ERROR_FLOAT_MULTIPLE_FAULTS",
        "message": "{EXCEPTION} Multiple floating point faults.",
    },
    0x00000277: {
        "code": "ERROR_FLOAT_MULTIPLE_TRAPS",
        "message": "{EXCEPTION} Multiple floating point traps.",
    },
    0x00000278: {
        "code": "ERROR_NOINTERFACE",
        "message": "The requested interface is not supported.",
    },
    0x00000279: {
        "code": "ERROR_DRIVER_FAILED_SLEEP",
        "message": (
            "{System Standby Failed} The driver %hs does not support standby mode."
            " Updating this driver might allow the system to go to standby mode."
        ),
    },
    0x0000027A: {
        "code": "ERROR_CORRUPT_SYSTEM_FILE",
        "message": "The system file %1 has become corrupt and has been replaced.",
    },
    0x0000027B: {
        "code": "ERROR_COMMITMENT_MINIMUM",
        "message": (
            "{Virtual Memory Minimum Too Low} Your system is low on virtual memory."
            " Windows is increasing the size of your virtual memory paging file. During"
            " this process, memory requests for some applications might be denied. For"
            " more information, see Help."
        ),
    },
    0x0000027C: {
        "code": "ERROR_PNP_RESTART_ENUMERATION",
        "message": "A device was removed so enumeration must be restarted.",
    },
    0x0000027D: {
        "code": "ERROR_SYSTEM_IMAGE_BAD_SIGNATURE",
        "message": (
            "{Fatal System Error} The system image %s is not properly signed. The file"
            " has been replaced with the signed file. The system has been shut down."
        ),
    },
    0x0000027E: {
        "code": "ERROR_PNP_REBOOT_REQUIRED",
        "message": "Device will not start without a reboot.",
    },
    0x0000027F: {
        "code": "ERROR_INSUFFICIENT_POWER",
        "message": "There is not enough power to complete the requested operation.",
    },
    0x00000281: {
        "code": "ERROR_SYSTEM_SHUTDOWN",
        "message": "The system is in the process of shutting down.",
    },
    0x00000282: {
        "code": "ERROR_PORT_NOT_SET",
        "message": (
            "An attempt to remove a process DebugPort was made, but a port was not"
            " already associated with the process."
        ),
    },
    0x00000283: {
        "code": "ERROR_DS_VERSION_CHECK_FAILURE",
        "message": (
            "This version of Windows is not compatible with the behavior version of"
            " directory forest, domain, or domain controller."
        ),
    },
    0x00000284: {
        "code": "ERROR_RANGE_NOT_FOUND",
        "message": "The specified range could not be found in the range list.",
    },
    0x00000286: {
        "code": "ERROR_NOT_SAFE_MODE_DRIVER",
        "message": (
            "The driver was not loaded because the system is booting into safe mode."
        ),
    },
    0x00000287: {
        "code": "ERROR_FAILED_DRIVER_ENTRY",
        "message": (
            "The driver was not loaded because it failed its initialization call."
        ),
    },
    0x00000288: {
        "code": "ERROR_DEVICE_ENUMERATION_ERROR",
        "message": (
            "The device encountered an error while applying power or reading the device"
            " configuration. This might be caused by a failure of your hardware or by a"
            " poor connection."
        ),
    },
    0x00000289: {
        "code": "ERROR_MOUNT_POINT_NOT_RESOLVED",
        "message": (
            "The create operation failed because the name contained at least one mount"
            " point that resolves to a volume to which the specified device object is"
            " not attached."
        ),
    },
    0x0000028A: {
        "code": "ERROR_INVALID_DEVICE_OBJECT_PARAMETER",
        "message": (
            "The device object parameter is either not a valid device object or is not"
            " attached to the volume specified by the file name."
        ),
    },
    0x0000028B: {
        "code": "ERROR_MCA_OCCURED",
        "message": (
            "A machine check error has occurred. Check the system event log for"
            " additional information."
        ),
    },
    0x0000028C: {
        "code": "ERROR_DRIVER_DATABASE_ERROR",
        "message": "There was an error [%2] processing the driver database.",
    },
    0x0000028D: {
        "code": "ERROR_SYSTEM_HIVE_TOO_LARGE",
        "message": "The system hive size has exceeded its limit.",
    },
    0x0000028E: {
        "code": "ERROR_DRIVER_FAILED_PRIOR_UNLOAD",
        "message": (
            "The driver could not be loaded because a previous version of the driver is"
            " still in memory."
        ),
    },
    0x0000028F: {
        "code": "ERROR_VOLSNAP_PREPARE_HIBERNATE",
        "message": (
            "{Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service"
            " prepares volume %hs for hibernation."
        ),
    },
    0x00000290: {
        "code": "ERROR_HIBERNATION_FAILURE",
        "message": (
            "The system has failed to hibernate (the error code is %hs). Hibernation"
            " will be disabled until the system is restarted."
        ),
    },
    0x00000299: {
        "code": "ERROR_FILE_SYSTEM_LIMITATION",
        "message": (
            "The requested operation could not be completed due to a file system"
            " limitation."
        ),
    },
    0x0000029C: {
        "code": "ERROR_ASSERTION_FAILURE",
        "message": "An assertion failure has occurred.",
    },
    0x0000029D: {
        "code": "ERROR_ACPI_ERROR",
        "message": (
            "An error occurred in the Advanced Configuration and Power Interface (ACPI)"
            " subsystem."
        ),
    },
    0x0000029E: {"code": "ERROR_WOW_ASSERTION", "message": "WOW assertion error."},
    0x0000029F: {
        "code": "ERROR_PNP_BAD_MPS_TABLE",
        "message": (
            "A device is missing in the system BIOS MultiProcessor Specification (MPS)"
            " table. This device will not be used. Contact your system vendor for"
            " system BIOS update."
        ),
    },
    0x000002A0: {
        "code": "ERROR_PNP_TRANSLATION_FAILED",
        "message": "A translator failed to translate resources.",
    },
    0x000002A1: {
        "code": "ERROR_PNP_IRQ_TRANSLATION_FAILED",
        "message": (
            "An interrupt request (IRQ) translator failed to translate resources."
        ),
    },
    0x000002A2: {
        "code": "ERROR_PNP_INVALID_ID",
        "message": "Driver %2 returned invalid ID for a child device (%3).",
    },
    0x000002A3: {
        "code": "ERROR_WAKE_SYSTEM_DEBUGGER",
        "message": (
            "{Kernel Debugger Awakened} the system debugger was awakened by an"
            " interrupt."
        ),
    },
    0x000002A4: {
        "code": "ERROR_HANDLES_CLOSED",
        "message": (
            "{Handles Closed} Handles to objects have been automatically closed because"
            " of the requested operation."
        ),
    },
    0x000002A5: {
        "code": "ERROR_EXTRANEOUS_INFORMATION",
        "message": (
            "{Too Much Information} The specified ACL contained more information than"
            " was expected."
        ),
    },
    0x000002A6: {
        "code": "ERROR_RXACT_COMMIT_NECESSARY",
        "message": (
            "This warning level status indicates that the transaction state already"
            " exists for the registry subtree, but that a transaction commit was"
            " previously aborted. The commit has NOT been completed, but it has not"
            " been rolled back either (so it can still be committed if desired)."
        ),
    },
    0x000002A7: {
        "code": "ERROR_MEDIA_CHECK",
        "message": "{Media Changed} The media might have changed.",
    },
    0x000002A8: {
        "code": "ERROR_GUID_SUBSTITUTION_MADE",
        "message": (
            "{GUID Substitution} During the translation of a GUID to a Windows SID, no"
            " administratively defined GUID prefix was found. A substitute prefix was"
            " used, which will not compromise system security. However, this might"
            " provide more restrictive access than intended."
        ),
    },
    0x000002A9: {
        "code": "ERROR_STOPPED_ON_SYMLINK",
        "message": "The create operation stopped after reaching a symbolic link.",
    },
    0x000002AA: {"code": "ERROR_LONGJUMP", "message": "A long jump has been executed."},
    0x000002AB: {
        "code": "ERROR_PLUGPLAY_QUERY_VETOED",
        "message": "The Plug and Play query operation was not successful.",
    },
    0x000002AC: {
        "code": "ERROR_UNWIND_CONSOLIDATE",
        "message": "A frame consolidation has been executed.",
    },
    0x000002AD: {
        "code": "ERROR_REGISTRY_HIVE_RECOVERED",
        "message": (
            "{Registry Hive Recovered} Registry hive (file): %hs was corrupted and it"
            " has been recovered. Some data might have been lost."
        ),
    },
    0x000002AE: {
        "code": "ERROR_DLL_MIGHT_BE_INSECURE",
        "message": (
            "The application is attempting to run executable code from the module %hs."
            " This might be insecure. An alternative, %hs, is available. Should the"
            " application use the secure module %hs?"
        ),
    },
    0x000002AF: {
        "code": "ERROR_DLL_MIGHT_BE_INCOMPATIBLE",
        "message": (
            "The application is loading executable code from the module %hs. This is"
            " secure, but might be incompatible with previous releases of the operating"
            " system. An alternative, %hs, is available. Should the application use the"
            " secure module %hs?"
        ),
    },
    0x000002B0: {
        "code": "ERROR_DBG_EXCEPTION_NOT_HANDLED",
        "message": "Debugger did not handle the exception.",
    },
    0x000002B1: {
        "code": "ERROR_DBG_REPLY_LATER",
        "message": "Debugger will reply later.",
    },
    0x000002B2: {
        "code": "ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE",
        "message": "Debugger cannot provide handle.",
    },
    0x000002B3: {
        "code": "ERROR_DBG_TERMINATE_THREAD",
        "message": "Debugger terminated thread.",
    },
    0x000002B4: {
        "code": "ERROR_DBG_TERMINATE_PROCESS",
        "message": "Debugger terminated process.",
    },
    0x000002B5: {"code": "ERROR_DBG_CONTROL_C", "message": "Debugger got control C."},
    0x000002B6: {
        "code": "ERROR_DBG_PRINTEXCEPTION_C",
        "message": "Debugger printed exception on control C.",
    },
    0x000002B7: {
        "code": "ERROR_DBG_RIPEXCEPTION",
        "message": "Debugger received Routing Information Protocol (RIP) exception.",
    },
    0x000002B8: {
        "code": "ERROR_DBG_CONTROL_BREAK",
        "message": "Debugger received control break.",
    },
    0x000002B9: {
        "code": "ERROR_DBG_COMMAND_EXCEPTION",
        "message": "Debugger command communication exception.",
    },
    0x000002BA: {
        "code": "ERROR_OBJECT_NAME_EXISTS",
        "message": (
            "{Object Exists} An attempt was made to create an object and the object"
            " name already existed."
        ),
    },
    0x000002BB: {
        "code": "ERROR_THREAD_WAS_SUSPENDED",
        "message": (
            "{Thread Suspended} A thread termination occurred while the thread was"
            " suspended. The thread was resumed and termination proceeded."
        ),
    },
    0x000002BC: {
        "code": "ERROR_IMAGE_NOT_AT_BASE",
        "message": (
            "{Image Relocated} An image file could not be mapped at the address"
            " specified in the image file. Local fixes must be performed on this image."
        ),
    },
    0x000002BD: {
        "code": "ERROR_RXACT_STATE_CREATED",
        "message": (
            "This informational level status indicates that a specified registry"
            " subtree transaction state did not yet exist and had to be created."
        ),
    },
    0x000002BE: {
        "code": "ERROR_SEGMENT_NOTIFICATION",
        "message": (
            "{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or"
            " moving an MS-DOS or Win16 program segment image. An exception is raised"
            " so a debugger can load, unload, or track symbols and breakpoints within"
            " these 16-bit segments."
        ),
    },
    0x000002BF: {
        "code": "ERROR_BAD_CURRENT_DIRECTORY",
        "message": (
            "{Invalid Current Directory} The process cannot switch to the startup"
            " current directory %hs. Select OK to set current directory to %hs, or"
            " select CANCEL to exit."
        ),
    },
    0x000002C0: {
        "code": "ERROR_FT_READ_RECOVERY_FROM_BACKUP",
        "message": (
            "{Redundant Read} To satisfy a read request, the NT fault-tolerant file"
            " system successfully read the requested data from a redundant copy. This"
            " was done because the file system encountered a failure on a member of the"
            " fault-tolerant volume, but it was unable to reassign the failing area of"
            " the device."
        ),
    },
    0x000002C1: {
        "code": "ERROR_FT_WRITE_RECOVERY",
        "message": (
            "{Redundant Write} To satisfy a write request, the Windows NT operating"
            " system fault-tolerant file system successfully wrote a redundant copy of"
            " the information. This was done because the file system encountered a"
            " failure on a member of the fault-tolerant volume, but it was not able to"
            " reassign the failing area of the device."
        ),
    },
    0x000002C2: {
        "code": "ERROR_IMAGE_MACHINE_TYPE_MISMATCH",
        "message": (
            "{Machine Type Mismatch} The image file %hs is valid, but is for a machine"
            " type other than the current machine. Select OK to continue, or CANCEL to"
            " fail the DLL load."
        ),
    },
    0x000002C3: {
        "code": "ERROR_RECEIVE_PARTIAL",
        "message": (
            "{Partial Data Received} The network transport returned partial data to its"
            " client. The remaining data will be sent later."
        ),
    },
    0x000002C4: {
        "code": "ERROR_RECEIVE_EXPEDITED",
        "message": (
            "{Expedited Data Received} The network transport returned data to its"
            " client that was marked as expedited by the remote system."
        ),
    },
    0x000002C5: {
        "code": "ERROR_RECEIVE_PARTIAL_EXPEDITED",
        "message": (
            "{Partial Expedited Data Received} The network transport returned partial"
            " data to its client and this data was marked as expedited by the remote"
            " system. The remaining data will be sent later."
        ),
    },
    0x000002C6: {
        "code": "ERROR_EVENT_DONE",
        "message": "{TDI Event Done} The TDI indication has completed successfully.",
    },
    0x000002C7: {
        "code": "ERROR_EVENT_PENDING",
        "message": (
            "{TDI Event Pending} The TDI indication has entered the pending state."
        ),
    },
    0x000002C8: {
        "code": "ERROR_CHECKING_FILE_SYSTEM",
        "message": "Checking file system on %wZ.",
    },
    0x000002C9: {
        "code": "ERROR_FATAL_APP_EXIT",
        "message": "{Fatal Application Exit} %hs.",
    },
    0x000002CA: {
        "code": "ERROR_PREDEFINED_HANDLE",
        "message": "The specified registry key is referenced by a predefined handle.",
    },
    0x000002CB: {
        "code": "ERROR_WAS_UNLOCKED",
        "message": (
            "{Page Unlocked} The page protection of a locked page was changed to 'No"
            " Access' and the page was unlocked from memory and from the process."
        ),
    },
    0x000002CD: {
        "code": "ERROR_WAS_LOCKED",
        "message": "{Page Locked} One of the pages to lock was already locked.",
    },
    0x000002CF: {
        "code": "ERROR_ALREADY_WIN32",
        "message": "The value already corresponds with a Win 32 error code.",
    },
    0x000002D0: {
        "code": "ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE",
        "message": (
            "{Machine Type Mismatch} The image file %hs is valid, but is for a machine"
            " type other than the current machine."
        ),
    },
    0x000002D1: {
        "code": "ERROR_NO_YIELD_PERFORMED",
        "message": (
            "A yield execution was performed and no thread was available to run."
        ),
    },
    0x000002D2: {
        "code": "ERROR_TIMER_RESUME_IGNORED",
        "message": "The resume flag to a timer API was ignored.",
    },
    0x000002D3: {
        "code": "ERROR_ARBITRATION_UNHANDLED",
        "message": (
            "The arbiter has deferred arbitration of these resources to its parent."
        ),
    },
    0x000002D4: {
        "code": "ERROR_CARDBUS_NOT_SUPPORTED",
        "message": (
            "The inserted CardBus device cannot be started because of a configuration"
            ' error on %hs"."'
        ),
    },
    0x000002D5: {
        "code": "ERROR_MP_PROCESSOR_MISMATCH",
        "message": (
            "The CPUs in this multiprocessor system are not all the same revision"
            " level. To use all processors the operating system restricts itself to the"
            " features of the least capable processor in the system. If problems occur"
            " with this system, contact the CPU manufacturer to see if this mix of"
            " processors is supported."
        ),
    },
    0x000002D6: {
        "code": "ERROR_HIBERNATED",
        "message": "The system was put into hibernation.",
    },
    0x000002D7: {
        "code": "ERROR_RESUME_HIBERNATION",
        "message": "The system was resumed from hibernation.",
    },
    0x000002D8: {
        "code": "ERROR_FIRMWARE_UPDATED",
        "message": (
            "Windows has detected that the system firmware (BIOS) was updated (previous"
            " firmware date = %2, current firmware date %3)."
        ),
    },
    0x000002D9: {
        "code": "ERROR_DRIVERS_LEAKING_LOCKED_PAGES",
        "message": (
            "A device driver is leaking locked I/O pages, causing system degradation."
            " The system has automatically enabled a tracking code to try and catch the"
            " culprit."
        ),
    },
    0x000002DA: {"code": "ERROR_WAKE_SYSTEM", "message": "The system has awoken."},
    0x000002DF: {
        "code": "ERROR_ABANDONED_WAIT_0",
        "message": "The call failed because the handle associated with it was closed.",
    },
    0x000002E4: {
        "code": "ERROR_ELEVATION_REQUIRED",
        "message": "The requested operation requires elevation.",
    },
    0x000002E5: {
        "code": "ERROR_REPARSE",
        "message": (
            "A reparse should be performed by the object manager because the name of"
            " the file resulted in a symbolic link."
        ),
    },
    0x000002E6: {
        "code": "ERROR_OPLOCK_BREAK_IN_PROGRESS",
        "message": (
            "An open/create operation completed while an oplock break is underway."
        ),
    },
    0x000002E7: {
        "code": "ERROR_VOLUME_MOUNTED",
        "message": "A new volume has been mounted by a file system.",
    },
    0x000002E8: {
        "code": "ERROR_RXACT_COMMITTED",
        "message": (
            "This success level status indicates that the transaction state already"
            " exists for the registry subtree, but that a transaction commit was"
            " previously aborted. The commit has now been completed."
        ),
    },
    0x000002E9: {
        "code": "ERROR_NOTIFY_CLEANUP",
        "message": (
            "This indicates that a notify change request has been completed due to"
            " closing the handle which made the notify change request."
        ),
    },
    0x000002EA: {
        "code": "ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED",
        "message": (
            "{Connect Failure on Primary Transport} An attempt was made to connect to"
            " the remote server %hs on the primary transport, but the connection"
            " failed. The computer was able to connect on a secondary transport."
        ),
    },
    0x000002EB: {
        "code": "ERROR_PAGE_FAULT_TRANSITION",
        "message": "Page fault was a transition fault.",
    },
    0x000002EC: {
        "code": "ERROR_PAGE_FAULT_DEMAND_ZERO",
        "message": "Page fault was a demand zero fault.",
    },
    0x000002ED: {
        "code": "ERROR_PAGE_FAULT_COPY_ON_WRITE",
        "message": "Page fault was a demand zero fault.",
    },
    0x000002EE: {
        "code": "ERROR_PAGE_FAULT_GUARD_PAGE",
        "message": "Page fault was a demand zero fault.",
    },
    0x000002EF: {
        "code": "ERROR_PAGE_FAULT_PAGING_FILE",
        "message": (
            "Page fault was satisfied by reading from a secondary storage device."
        ),
    },
    0x000002F0: {
        "code": "ERROR_CACHE_PAGE_LOCKED",
        "message": "Cached page was locked during operation.",
    },
    0x000002F1: {
        "code": "ERROR_CRASH_DUMP",
        "message": "Crash dump exists in paging file.",
    },
    0x000002F2: {
        "code": "ERROR_BUFFER_ALL_ZEROS",
        "message": "Specified buffer contains all zeros.",
    },
    0x000002F3: {
        "code": "ERROR_REPARSE_OBJECT",
        "message": (
            "A reparse should be performed by the object manager because the name of"
            " the file resulted in a symbolic link."
        ),
    },
    0x000002F4: {
        "code": "ERROR_RESOURCE_REQUIREMENTS_CHANGED",
        "message": (
            "The device has succeeded a query-stop and its resource requirements have"
            " changed."
        ),
    },
    0x000002F5: {
        "code": "ERROR_TRANSLATION_COMPLETE",
        "message": (
            "The translator has translated these resources into the global space and no"
            " further translations should be performed."
        ),
    },
    0x000002F6: {
        "code": "ERROR_NOTHING_TO_TERMINATE",
        "message": "A process being terminated has no threads to terminate.",
    },
    0x000002F7: {
        "code": "ERROR_PROCESS_NOT_IN_JOB",
        "message": "The specified process is not part of a job.",
    },
    0x000002F8: {
        "code": "ERROR_PROCESS_IN_JOB",
        "message": "The specified process is part of a job.",
    },
    0x000002F9: {
        "code": "ERROR_VOLSNAP_HIBERNATE_READY",
        "message": (
            "{Volume Shadow Copy Service} The system is now ready for hibernation."
        ),
    },
    0x000002FA: {
        "code": "ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY",
        "message": (
            "A file system or file system filter driver has successfully completed an"
            " FsFilter operation."
        ),
    },
    0x000002FB: {
        "code": "ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED",
        "message": "The specified interrupt vector was already connected.",
    },
    0x000002FC: {
        "code": "ERROR_INTERRUPT_STILL_CONNECTED",
        "message": "The specified interrupt vector is still connected.",
    },
    0x000002FD: {
        "code": "ERROR_WAIT_FOR_OPLOCK",
        "message": "An operation is blocked waiting for an oplock.",
    },
    0x000002FE: {
        "code": "ERROR_DBG_EXCEPTION_HANDLED",
        "message": "Debugger handled exception.",
    },
    0x000002FF: {"code": "ERROR_DBG_CONTINUE", "message": "Debugger continued."},
    0x00000300: {
        "code": "ERROR_CALLBACK_POP_STACK",
        "message": (
            "An exception occurred in a user mode callback and the kernel callback"
            " frame should be removed."
        ),
    },
    0x00000301: {
        "code": "ERROR_COMPRESSION_DISABLED",
        "message": "Compression is disabled for this volume.",
    },
    0x00000302: {
        "code": "ERROR_CANTFETCHBACKWARDS",
        "message": "The data provider cannot fetch backward through a result set.",
    },
    0x00000303: {
        "code": "ERROR_CANTSCROLLBACKWARDS",
        "message": "The data provider cannot scroll backward through a result set.",
    },
    0x00000304: {
        "code": "ERROR_ROWSNOTRELEASED",
        "message": (
            "The data provider requires that previously fetched data is released before"
            " asking for more data."
        ),
    },
    0x00000305: {
        "code": "ERROR_BAD_ACCESSOR_FLAGS",
        "message": (
            "The data provider was not able to interpret the flags set for a column"
            " binding in an accessor."
        ),
    },
    0x00000306: {
        "code": "ERROR_ERRORS_ENCOUNTERED",
        "message": "One or more errors occurred while processing the request.",
    },
    0x00000307: {
        "code": "ERROR_NOT_CAPABLE",
        "message": "The implementation is not capable of performing the request.",
    },
    0x00000308: {
        "code": "ERROR_REQUEST_OUT_OF_SEQUENCE",
        "message": (
            "The client of a component requested an operation that is not valid given"
            " the state of the component instance."
        ),
    },
    0x00000309: {
        "code": "ERROR_VERSION_PARSE_ERROR",
        "message": "A version number could not be parsed.",
    },
    0x0000030A: {
        "code": "ERROR_BADSTARTPOSITION",
        "message": "The iterator's start position is invalid.",
    },
    0x0000030B: {
        "code": "ERROR_MEMORY_HARDWARE",
        "message": "The hardware has reported an uncorrectable memory error.",
    },
    0x0000030C: {
        "code": "ERROR_DISK_REPAIR_DISABLED",
        "message": "The attempted operation required self-healing to be enabled.",
    },
    0x0000030D: {
        "code": "ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE",
        "message": (
            "The Desktop heap encountered an error while allocating session memory."
            " There is more information in the system event log."
        ),
    },
    0x0000030E: {
        "code": "ERROR_SYSTEM_POWERSTATE_TRANSITION",
        "message": "The system power state is transitioning from %2 to %3.",
    },
    0x0000030F: {
        "code": "ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION",
        "message": (
            "The system power state is transitioning from %2 to %3 but could enter %4."
        ),
    },
    0x00000310: {
        "code": "ERROR_MCA_EXCEPTION",
        "message": "A thread is getting dispatched with MCA EXCEPTION because of MCA.",
    },
    0x00000311: {
        "code": "ERROR_ACCESS_AUDIT_BY_POLICY",
        "message": "Access to %1 is monitored by policy rule %2.",
    },
    0x00000312: {
        "code": "ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY",
        "message": (
            "Access to %1 has been restricted by your administrator by policy rule %2."
        ),
    },
    0x00000313: {
        "code": "ERROR_ABANDON_HIBERFILE",
        "message": (
            "A valid hibernation file has been invalidated and should be abandoned."
        ),
    },
    0x00000314: {
        "code": "ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED",
        "message": (
            "{Delayed Write Failed} Windows was unable to save all the data for the"
            " file %hs; the data has been lost. This error can be caused by network"
            " connectivity issues. Try to save this file elsewhere."
        ),
    },
    0x00000315: {
        "code": "ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR",
        "message": (
            "{Delayed Write Failed} Windows was unable to save all the data for the"
            " file %hs; the data has been lost. This error was returned by the server"
            " on which the file exists. Try to save this file elsewhere."
        ),
    },
    0x00000316: {
        "code": "ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR",
        "message": (
            "{Delayed Write Failed} Windows was unable to save all the data for the"
            " file %hs; the data has been lost. This error can be caused if the device"
            " has been removed or the media is write-protected."
        ),
    },
    0x000003E2: {
        "code": "ERROR_EA_ACCESS_DENIED",
        "message": "Access to the extended attribute was denied.",
    },
    0x000003E3: {
        "code": "ERROR_OPERATION_ABORTED",
        "message": (
            "The I/O operation has been aborted because of either a thread exit or an"
            " application request."
        ),
    },
    0x000003E4: {
        "code": "ERROR_IO_INCOMPLETE",
        "message": "Overlapped I/O event is not in a signaled state.",
    },
    0x000003E5: {
        "code": "ERROR_IO_PENDING",
        "message": "Overlapped I/O operation is in progress.",
    },
    0x000003E6: {
        "code": "ERROR_NOACCESS",
        "message": "Invalid access to memory location.",
    },
    0x000003E7: {
        "code": "ERROR_SWAPERROR",
        "message": "Error performing in-page operation.",
    },
    0x000003E9: {
        "code": "ERROR_STACK_OVERFLOW",
        "message": "Recursion too deep; the stack overflowed.",
    },
    0x000003EA: {
        "code": "ERROR_INVALID_MESSAGE",
        "message": "The window cannot act on the sent message.",
    },
    0x000003EB: {
        "code": "ERROR_CAN_NOT_COMPLETE",
        "message": "Cannot complete this function.",
    },
    0x000003EC: {"code": "ERROR_INVALID_FLAGS", "message": "Invalid flags."},
    0x000003ED: {
        "code": "ERROR_UNRECOGNIZED_VOLUME",
        "message": (
            "The volume does not contain a recognized file system. Be sure that all"
            " required file system drivers are loaded and that the volume is not"
            " corrupted."
        ),
    },
    0x000003EE: {
        "code": "ERROR_FILE_INVALID",
        "message": (
            "The volume for a file has been externally altered so that the opened file"
            " is no longer valid."
        ),
    },
    0x000003EF: {
        "code": "ERROR_FULLSCREEN_MODE",
        "message": "The requested operation cannot be performed in full-screen mode.",
    },
    0x000003F0: {
        "code": "ERROR_NO_TOKEN",
        "message": "An attempt was made to reference a token that does not exist.",
    },
    0x000003F1: {
        "code": "ERROR_BADDB",
        "message": "The configuration registry database is corrupt.",
    },
    0x000003F2: {
        "code": "ERROR_BADKEY",
        "message": "The configuration registry key is invalid.",
    },
    0x000003F3: {
        "code": "ERROR_CANTOPEN",
        "message": "The configuration registry key could not be opened.",
    },
    0x000003F4: {
        "code": "ERROR_CANTREAD",
        "message": "The configuration registry key could not be read.",
    },
    0x000003F5: {
        "code": "ERROR_CANTWRITE",
        "message": "The configuration registry key could not be written.",
    },
    0x000003F6: {
        "code": "ERROR_REGISTRY_RECOVERED",
        "message": (
            "One of the files in the registry database had to be recovered by use of a"
            " log or alternate copy. The recovery was successful."
        ),
    },
    0x000003F7: {
        "code": "ERROR_REGISTRY_CORRUPT",
        "message": (
            "The registry is corrupted. The structure of one of the files containing"
            " registry data is corrupted, or the system's memory image of the file is"
            " corrupted, or the file could not be recovered because the alternate copy"
            " or log was absent or corrupted."
        ),
    },
    0x000003F8: {
        "code": "ERROR_REGISTRY_IO_FAILED",
        "message": (
            "An I/O operation initiated by the registry failed and cannot be recovered."
            " The registry could not read in, write out, or flush one of the files that"
            " contain the system's image of the registry."
        ),
    },
    0x000003F9: {
        "code": "ERROR_NOT_REGISTRY_FILE",
        "message": (
            "The system attempted to load or restore a file into the registry, but the"
            " specified file is not in a registry file format."
        ),
    },
    0x000003FA: {
        "code": "ERROR_KEY_DELETED",
        "message": (
            "Illegal operation attempted on a registry key that has been marked for"
            " deletion."
        ),
    },
    0x000003FB: {
        "code": "ERROR_NO_LOG_SPACE",
        "message": "System could not allocate the required space in a registry log.",
    },
    0x000003FC: {
        "code": "ERROR_KEY_HAS_CHILDREN",
        "message": (
            "Cannot create a symbolic link in a registry key that already has subkeys"
            " or values."
        ),
    },
    0x000003FD: {
        "code": "ERROR_CHILD_MUST_BE_VOLATILE",
        "message": "Cannot create a stable subkey under a volatile parent key.",
    },
    0x000003FE: {
        "code": "ERROR_NOTIFY_ENUM_DIR",
        "message": (
            "A notify change request is being completed and the information is not"
            " being returned in the caller's buffer. The caller now needs to enumerate"
            " the files to find the changes."
        ),
    },
    0x0000041B: {
        "code": "ERROR_DEPENDENT_SERVICES_RUNNING",
        "message": (
            "A stop control has been sent to a service that other running services are"
            " dependent on."
        ),
    },
    0x0000041C: {
        "code": "ERROR_INVALID_SERVICE_CONTROL",
        "message": "The requested control is not valid for this service.",
    },
    0x0000041D: {
        "code": "ERROR_SERVICE_REQUEST_TIMEOUT",
        "message": (
            "The service did not respond to the start or control request in a timely"
            " fashion."
        ),
    },
    0x0000041E: {
        "code": "ERROR_SERVICE_NO_THREAD",
        "message": "A thread could not be created for the service.",
    },
    0x0000041F: {
        "code": "ERROR_SERVICE_DATABASE_LOCKED",
        "message": "The service database is locked.",
    },
    0x00000420: {
        "code": "ERROR_SERVICE_ALREADY_RUNNING",
        "message": "An instance of the service is already running.",
    },
    0x00000421: {
        "code": "ERROR_INVALID_SERVICE_ACCOUNT",
        "message": (
            "The account name is invalid or does not exist, or the password is invalid"
            " for the account name specified."
        ),
    },
    0x00000422: {
        "code": "ERROR_SERVICE_DISABLED",
        "message": (
            "The service cannot be started, either because it is disabled or because it"
            " has no enabled devices associated with it."
        ),
    },
    0x00000423: {
        "code": "ERROR_CIRCULAR_DEPENDENCY",
        "message": "Circular service dependency was specified.",
    },
    0x00000424: {
        "code": "ERROR_SERVICE_DOES_NOT_EXIST",
        "message": "The specified service does not exist as an installed service.",
    },
    0x00000425: {
        "code": "ERROR_SERVICE_CANNOT_ACCEPT_CTRL",
        "message": "The service cannot accept control messages at this time.",
    },
    0x00000426: {
        "code": "ERROR_SERVICE_NOT_ACTIVE",
        "message": "The service has not been started.",
    },
    0x00000427: {
        "code": "ERROR_FAILED_SERVICE_CONTROLLER_CONNECT",
        "message": "The service process could not connect to the service controller.",
    },
    0x00000428: {
        "code": "ERROR_EXCEPTION_IN_SERVICE",
        "message": (
            "An exception occurred in the service when handling the control request."
        ),
    },
    0x00000429: {
        "code": "ERROR_DATABASE_DOES_NOT_EXIST",
        "message": "The database specified does not exist.",
    },
    0x0000042A: {
        "code": "ERROR_SERVICE_SPECIFIC_ERROR",
        "message": "The service has returned a service-specific error code.",
    },
    0x0000042B: {
        "code": "ERROR_PROCESS_ABORTED",
        "message": "The process terminated unexpectedly.",
    },
    0x0000042C: {
        "code": "ERROR_SERVICE_DEPENDENCY_FAIL",
        "message": "The dependency service or group failed to start.",
    },
    0x0000042D: {
        "code": "ERROR_SERVICE_LOGON_FAILED",
        "message": "The service did not start due to a logon failure.",
    },
    0x0000042E: {
        "code": "ERROR_SERVICE_START_HANG",
        "message": (
            "After starting, the service stopped responding in a start-pending state."
        ),
    },
    0x0000042F: {
        "code": "ERROR_INVALID_SERVICE_LOCK",
        "message": "The specified service database lock is invalid.",
    },
    0x00000430: {
        "code": "ERROR_SERVICE_MARKED_FOR_DELETE",
        "message": "The specified service has been marked for deletion.",
    },
    0x00000431: {
        "code": "ERROR_SERVICE_EXISTS",
        "message": "The specified service already exists.",
    },
    0x00000432: {
        "code": "ERROR_ALREADY_RUNNING_LKG",
        "message": (
            "The system is currently running with the last-known-good configuration."
        ),
    },
    0x00000433: {
        "code": "ERROR_SERVICE_DEPENDENCY_DELETED",
        "message": (
            "The dependency service does not exist or has been marked for deletion."
        ),
    },
    0x00000434: {
        "code": "ERROR_BOOT_ALREADY_ACCEPTED",
        "message": (
            "The current boot has already been accepted for use as the last-known-good"
            " control set."
        ),
    },
    0x00000435: {
        "code": "ERROR_SERVICE_NEVER_STARTED",
        "message": (
            "No attempts to start the service have been made since the last boot."
        ),
    },
    0x00000436: {
        "code": "ERROR_DUPLICATE_SERVICE_NAME",
        "message": (
            "The name is already in use as either a service name or a service display"
            " name."
        ),
    },
    0x00000437: {
        "code": "ERROR_DIFFERENT_SERVICE_ACCOUNT",
        "message": (
            "The account specified for this service is different from the account"
            " specified for other services running in the same process."
        ),
    },
    0x00000438: {
        "code": "ERROR_CANNOT_DETECT_DRIVER_FAILURE",
        "message": (
            "Failure actions can only be set for Win32 services, not for drivers."
        ),
    },
    0x00000439: {
        "code": "ERROR_CANNOT_DETECT_PROCESS_ABORT",
        "message": (
            "This service runs in the same process as the service control manager."
            " Therefore, the service control manager cannot take action if this"
            " service's process terminates unexpectedly."
        ),
    },
    0x0000043A: {
        "code": "ERROR_NO_RECOVERY_PROGRAM",
        "message": "No recovery program has been configured for this service.",
    },
    0x0000043B: {
        "code": "ERROR_SERVICE_NOT_IN_EXE",
        "message": (
            "The executable program that this service is configured to run in does not"
            " implement the service."
        ),
    },
    0x0000043C: {
        "code": "ERROR_NOT_SAFEBOOT_SERVICE",
        "message": "This service cannot be started in Safe Mode.",
    },
    0x0000044C: {
        "code": "ERROR_END_OF_MEDIA",
        "message": "The physical end of the tape has been reached.",
    },
    0x0000044D: {
        "code": "ERROR_FILEMARK_DETECTED",
        "message": "A tape access reached a filemark.",
    },
    0x0000044E: {
        "code": "ERROR_BEGINNING_OF_MEDIA",
        "message": "The beginning of the tape or a partition was encountered.",
    },
    0x0000044F: {
        "code": "ERROR_SETMARK_DETECTED",
        "message": "A tape access reached the end of a set of files.",
    },
    0x00000450: {
        "code": "ERROR_NO_DATA_DETECTED",
        "message": "No more data is on the tape.",
    },
    0x00000451: {
        "code": "ERROR_PARTITION_FAILURE",
        "message": "Tape could not be partitioned.",
    },
    0x00000452: {
        "code": "ERROR_INVALID_BLOCK_LENGTH",
        "message": (
            "When accessing a new tape of a multivolume partition, the current block"
            " size is incorrect."
        ),
    },
    0x00000453: {
        "code": "ERROR_DEVICE_NOT_PARTITIONED",
        "message": "Tape partition information could not be found when loading a tape.",
    },
    0x00000454: {
        "code": "ERROR_UNABLE_TO_LOCK_MEDIA",
        "message": "Unable to lock the media eject mechanism.",
    },
    0x00000455: {
        "code": "ERROR_UNABLE_TO_UNLOAD_MEDIA",
        "message": "Unable to unload the media.",
    },
    0x00000456: {
        "code": "ERROR_MEDIA_CHANGED",
        "message": "The media in the drive might have changed.",
    },
    0x00000457: {"code": "ERROR_BUS_RESET", "message": "The I/O bus was reset."},
    0x00000458: {"code": "ERROR_NO_MEDIA_IN_DRIVE", "message": "No media in drive."},
    0x00000459: {
        "code": "ERROR_NO_UNICODE_TRANSLATION",
        "message": (
            "No mapping for the Unicode character exists in the target multibyte code"
            " page."
        ),
    },
    0x0000045A: {
        "code": "ERROR_DLL_INIT_FAILED",
        "message": "A DLL initialization routine failed.",
    },
    0x0000045B: {
        "code": "ERROR_SHUTDOWN_IN_PROGRESS",
        "message": "A system shutdown is in progress.",
    },
    0x0000045C: {
        "code": "ERROR_NO_SHUTDOWN_IN_PROGRESS",
        "message": (
            "Unable to abort the system shutdown because no shutdown was in progress."
        ),
    },
    0x0000045D: {
        "code": "ERROR_IO_DEVICE",
        "message": "The request could not be performed because of an I/O device error.",
    },
    0x0000045E: {
        "code": "ERROR_SERIAL_NO_DEVICE",
        "message": (
            "No serial device was successfully initialized. The serial driver will"
            " unload."
        ),
    },
    0x0000045F: {
        "code": "ERROR_IRQ_BUSY",
        "message": (
            "Unable to open a device that was sharing an IRQ with other devices. At"
            " least one other device that uses that IRQ was already opened."
        ),
    },
    0x00000460: {
        "code": "ERROR_MORE_WRITES",
        "message": (
            "A serial I/O operation was completed by another write to the serial port."
            " (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)"
        ),
    },
    0x00000461: {
        "code": "ERROR_COUNTER_TIMEOUT",
        "message": (
            "A serial I/O operation completed because the time-out period expired. (The"
            " IOCTL_SERIAL_XOFF_COUNTER did not reach zero.)"
        ),
    },
    0x00000462: {
        "code": "ERROR_FLOPPY_ID_MARK_NOT_FOUND",
        "message": "No ID address mark was found on the floppy disk.",
    },
    0x00000463: {
        "code": "ERROR_FLOPPY_WRONG_CYLINDER",
        "message": (
            "Mismatch between the floppy disk sector ID field and the floppy disk"
            " controller track address."
        ),
    },
    0x00000464: {
        "code": "ERROR_FLOPPY_UNKNOWN_ERROR",
        "message": (
            "The floppy disk controller reported an error that is not recognized by the"
            " floppy disk driver."
        ),
    },
    0x00000465: {
        "code": "ERROR_FLOPPY_BAD_REGISTERS",
        "message": (
            "The floppy disk controller returned inconsistent results in its registers."
        ),
    },
    0x00000466: {
        "code": "ERROR_DISK_RECALIBRATE_FAILED",
        "message": (
            "While accessing the hard disk, a recalibrate operation failed, even after"
            " retries."
        ),
    },
    0x00000467: {
        "code": "ERROR_DISK_OPERATION_FAILED",
        "message": (
            "While accessing the hard disk, a disk operation failed even after retries."
        ),
    },
    0x00000468: {
        "code": "ERROR_DISK_RESET_FAILED",
        "message": (
            "While accessing the hard disk, a disk controller reset was needed, but"
            " that also failed."
        ),
    },
    0x00000469: {
        "code": "ERROR_EOM_OVERFLOW",
        "message": "Physical end of tape encountered.",
    },
    0x0000046A: {
        "code": "ERROR_NOT_ENOUGH_SERVER_MEMORY",
        "message": "Not enough server storage is available to process this command.",
    },
    0x0000046B: {
        "code": "ERROR_POSSIBLE_DEADLOCK",
        "message": "A potential deadlock condition has been detected.",
    },
    0x0000046C: {
        "code": "ERROR_MAPPED_ALIGNMENT",
        "message": (
            "The base address or the file offset specified does not have the proper"
            " alignment."
        ),
    },
    0x00000474: {
        "code": "ERROR_SET_POWER_STATE_VETOED",
        "message": (
            "An attempt to change the system power state was vetoed by another"
            " application or driver."
        ),
    },
    0x00000475: {
        "code": "ERROR_SET_POWER_STATE_FAILED",
        "message": (
            "The system BIOS failed an attempt to change the system power state."
        ),
    },
    0x00000476: {
        "code": "ERROR_TOO_MANY_LINKS",
        "message": (
            "An attempt was made to create more links on a file than the file system"
            " supports."
        ),
    },
    0x0000047E: {
        "code": "ERROR_OLD_WIN_VERSION",
        "message": "The specified program requires a newer version of Windows.",
    },
    0x0000047F: {
        "code": "ERROR_APP_WRONG_OS",
        "message": "The specified program is not a Windows or MS-DOS program.",
    },
    0x00000480: {
        "code": "ERROR_SINGLE_INSTANCE_APP",
        "message": "Cannot start more than one instance of the specified program.",
    },
    0x00000481: {
        "code": "ERROR_RMODE_APP",
        "message": (
            "The specified program was written for an earlier version of Windows."
        ),
    },
    0x00000482: {
        "code": "ERROR_INVALID_DLL",
        "message": (
            "One of the library files needed to run this application is damaged."
        ),
    },
    0x00000483: {
        "code": "ERROR_NO_ASSOCIATION",
        "message": (
            "No application is associated with the specified file for this operation."
        ),
    },
    0x00000484: {
        "code": "ERROR_DDE_FAIL",
        "message": "An error occurred in sending the command to the application.",
    },
    0x00000485: {
        "code": "ERROR_DLL_NOT_FOUND",
        "message": (
            "One of the library files needed to run this application cannot be found."
        ),
    },
    0x00000486: {
        "code": "ERROR_NO_MORE_USER_HANDLES",
        "message": (
            "The current process has used all of its system allowance of handles for"
            " Windows manager objects."
        ),
    },
    0x00000487: {
        "code": "ERROR_MESSAGE_SYNC_ONLY",
        "message": "The message can be used only with synchronous operations.",
    },
    0x00000488: {
        "code": "ERROR_SOURCE_ELEMENT_EMPTY",
        "message": "The indicated source element has no media.",
    },
    0x00000489: {
        "code": "ERROR_DESTINATION_ELEMENT_FULL",
        "message": "The indicated destination element already contains media.",
    },
    0x0000048A: {
        "code": "ERROR_ILLEGAL_ELEMENT_ADDRESS",
        "message": "The indicated element does not exist.",
    },
    0x0000048B: {
        "code": "ERROR_MAGAZINE_NOT_PRESENT",
        "message": "The indicated element is part of a magazine that is not present.",
    },
    0x0000048C: {
        "code": "ERROR_DEVICE_REINITIALIZATION_NEEDED",
        "message": (
            "The indicated device requires re-initialization due to hardware errors."
        ),
    },
    0x0000048D: {
        "code": "ERROR_DEVICE_REQUIRES_CLEANING",
        "message": (
            "The device has indicated that cleaning is required before further"
            " operations are attempted."
        ),
    },
    0x0000048E: {
        "code": "ERROR_DEVICE_DOOR_OPEN",
        "message": "The device has indicated that its door is open.",
    },
    0x0000048F: {
        "code": "ERROR_DEVICE_NOT_CONNECTED",
        "message": "The device is not connected.",
    },
    0x00000490: {"code": "ERROR_NOT_FOUND", "message": "Element not found."},
    0x00000491: {
        "code": "ERROR_NO_MATCH",
        "message": "There was no match for the specified key in the index.",
    },
    0x00000492: {
        "code": "ERROR_SET_NOT_FOUND",
        "message": "The property set specified does not exist on the object.",
    },
    0x00000493: {
        "code": "ERROR_POINT_NOT_FOUND",
        "message": "The point passed to GetMouseMovePoints is not in the buffer.",
    },
    0x00000494: {
        "code": "ERROR_NO_TRACKING_SERVICE",
        "message": "The tracking (workstation) service is not running.",
    },
    0x00000495: {
        "code": "ERROR_NO_VOLUME_ID",
        "message": "The volume ID could not be found.",
    },
    0x00000497: {
        "code": "ERROR_UNABLE_TO_REMOVE_REPLACED",
        "message": "Unable to remove the file to be replaced.",
    },
    0x00000498: {
        "code": "ERROR_UNABLE_TO_MOVE_REPLACEMENT",
        "message": (
            "Unable to move the replacement file to the file to be replaced. The file"
            " to be replaced has retained its original name."
        ),
    },
    0x00000499: {
        "code": "ERROR_UNABLE_TO_MOVE_REPLACEMENT_2",
        "message": (
            "Unable to move the replacement file to the file to be replaced. The file"
            " to be replaced has been renamed using the backup name."
        ),
    },
    0x0000049A: {
        "code": "ERROR_JOURNAL_DELETE_IN_PROGRESS",
        "message": "The volume change journal is being deleted.",
    },
    0x0000049B: {
        "code": "ERROR_JOURNAL_NOT_ACTIVE",
        "message": "The volume change journal is not active.",
    },
    0x0000049C: {
        "code": "ERROR_POTENTIAL_FILE_FOUND",
        "message": "A file was found, but it might not be the correct file.",
    },
    0x0000049D: {
        "code": "ERROR_JOURNAL_ENTRY_DELETED",
        "message": "The journal entry has been deleted from the journal.",
    },
    0x000004A6: {
        "code": "ERROR_SHUTDOWN_IS_SCHEDULED",
        "message": "A system shutdown has already been scheduled.",
    },
    0x000004A7: {
        "code": "ERROR_SHUTDOWN_USERS_LOGGED_ON",
        "message": (
            "The system shutdown cannot be initiated because there are other users"
            " logged on to the computer."
        ),
    },
    0x000004B0: {
        "code": "ERROR_BAD_DEVICE",
        "message": "The specified device name is invalid.",
    },
    0x000004B1: {
        "code": "ERROR_CONNECTION_UNAVAIL",
        "message": (
            "The device is not currently connected but it is a remembered connection."
        ),
    },
    0x000004B2: {
        "code": "ERROR_DEVICE_ALREADY_REMEMBERED",
        "message": (
            "The local device name has a remembered connection to another network"
            " resource."
        ),
    },
    0x000004B3: {
        "code": "ERROR_NO_NET_OR_BAD_PATH",
        "message": (
            "The network path was either typed incorrectly, does not exist, or the"
            " network provider is not currently available. Try retyping the path or"
            " contact your network administrator."
        ),
    },
    0x000004B4: {
        "code": "ERROR_BAD_PROVIDER",
        "message": "The specified network provider name is invalid.",
    },
    0x000004B5: {
        "code": "ERROR_CANNOT_OPEN_PROFILE",
        "message": "Unable to open the network connection profile.",
    },
    0x000004B6: {
        "code": "ERROR_BAD_PROFILE",
        "message": "The network connection profile is corrupted.",
    },
    0x000004B7: {
        "code": "ERROR_NOT_CONTAINER",
        "message": "Cannot enumerate a noncontainer.",
    },
    0x000004B8: {
        "code": "ERROR_EXTENDED_ERROR",
        "message": "An extended error has occurred.",
    },
    0x000004B9: {
        "code": "ERROR_INVALID_GROUPNAME",
        "message": "The format of the specified group name is invalid.",
    },
    0x000004BA: {
        "code": "ERROR_INVALID_COMPUTERNAME",
        "message": "The format of the specified computer name is invalid.",
    },
    0x000004BB: {
        "code": "ERROR_INVALID_EVENTNAME",
        "message": "The format of the specified event name is invalid.",
    },
    0x000004BC: {
        "code": "ERROR_INVALID_DOMAINNAME",
        "message": "The format of the specified domain name is invalid.",
    },
    0x000004BD: {
        "code": "ERROR_INVALID_SERVICENAME",
        "message": "The format of the specified service name is invalid.",
    },
    0x000004BE: {
        "code": "ERROR_INVALID_NETNAME",
        "message": "The format of the specified network name is invalid.",
    },
    0x000004BF: {
        "code": "ERROR_INVALID_SHARENAME",
        "message": "The format of the specified share name is invalid.",
    },
    0x000004C0: {
        "code": "ERROR_INVALID_PASSWORDNAME",
        "message": "The format of the specified password is invalid.",
    },
    0x000004C1: {
        "code": "ERROR_INVALID_MESSAGENAME",
        "message": "The format of the specified message name is invalid.",
    },
    0x000004C2: {
        "code": "ERROR_INVALID_MESSAGEDEST",
        "message": "The format of the specified message destination is invalid.",
    },
    0x000004C3: {
        "code": "ERROR_SESSION_CREDENTIAL_CONFLICT",
        "message": (
            "Multiple connections to a server or shared resource by the same user,"
            " using more than one user name, are not allowed. Disconnect all previous"
            " connections to the server or shared resource and try again."
        ),
    },
    0x000004C4: {
        "code": "ERROR_REMOTE_SESSION_LIMIT_EXCEEDED",
        "message": (
            "An attempt was made to establish a session to a network server, but there"
            " are already too many sessions established to that server."
        ),
    },
    0x000004C5: {
        "code": "ERROR_DUP_DOMAINNAME",
        "message": (
            "The workgroup or domain name is already in use by another computer on the"
            " network."
        ),
    },
    0x000004C6: {
        "code": "ERROR_NO_NETWORK",
        "message": "The network is not present or not started.",
    },
    0x000004C7: {
        "code": "ERROR_CANCELLED",
        "message": "The operation was canceled by the user.",
    },
    0x000004C8: {
        "code": "ERROR_USER_MAPPED_FILE",
        "message": (
            "The requested operation cannot be performed on a file with a user-mapped"
            " section open."
        ),
    },
    0x000004C9: {
        "code": "ERROR_CONNECTION_REFUSED",
        "message": "The remote system refused the network connection.",
    },
    0x000004CA: {
        "code": "ERROR_GRACEFUL_DISCONNECT",
        "message": "The network connection was gracefully closed.",
    },
    0x000004CB: {
        "code": "ERROR_ADDRESS_ALREADY_ASSOCIATED",
        "message": (
            "The network transport endpoint already has an address associated with it."
        ),
    },
    0x000004CC: {
        "code": "ERROR_ADDRESS_NOT_ASSOCIATED",
        "message": "An address has not yet been associated with the network endpoint.",
    },
    0x000004CD: {
        "code": "ERROR_CONNECTION_INVALID",
        "message": "An operation was attempted on a nonexistent network connection.",
    },
    0x000004CE: {
        "code": "ERROR_CONNECTION_ACTIVE",
        "message": (
            "An invalid operation was attempted on an active network connection."
        ),
    },
    0x000004CF: {
        "code": "ERROR_NETWORK_UNREACHABLE",
        "message": (
            "The network location cannot be reached. For information about network"
            " troubleshooting, see Windows Help."
        ),
    },
    0x000004D0: {
        "code": "ERROR_HOST_UNREACHABLE",
        "message": (
            "The network location cannot be reached. For information about network"
            " troubleshooting, see Windows Help."
        ),
    },
    0x000004D1: {
        "code": "ERROR_PROTOCOL_UNREACHABLE",
        "message": (
            "The network location cannot be reached. For information about network"
            " troubleshooting, see Windows Help."
        ),
    },
    0x000004D2: {
        "code": "ERROR_PORT_UNREACHABLE",
        "message": (
            "No service is operating at the destination network endpoint on the remote"
            " system."
        ),
    },
    0x000004D3: {
        "code": "ERROR_REQUEST_ABORTED",
        "message": "The request was aborted.",
    },
    0x000004D4: {
        "code": "ERROR_CONNECTION_ABORTED",
        "message": "The network connection was aborted by the local system.",
    },
    0x000004D5: {
        "code": "ERROR_RETRY",
        "message": "The operation could not be completed. A retry should be performed.",
    },
    0x000004D6: {
        "code": "ERROR_CONNECTION_COUNT_LIMIT",
        "message": (
            "A connection to the server could not be made because the limit on the"
            " number of concurrent connections for this account has been reached."
        ),
    },
    0x000004D7: {
        "code": "ERROR_LOGIN_TIME_RESTRICTION",
        "message": (
            "Attempting to log on during an unauthorized time of day for this account."
        ),
    },
    0x000004D8: {
        "code": "ERROR_LOGIN_WKSTA_RESTRICTION",
        "message": "The account is not authorized to log on from this station.",
    },
    0x000004D9: {
        "code": "ERROR_INCORRECT_ADDRESS",
        "message": "The network address could not be used for the operation requested.",
    },
    0x000004DA: {
        "code": "ERROR_ALREADY_REGISTERED",
        "message": "The service is already registered.",
    },
    0x000004DB: {
        "code": "ERROR_SERVICE_NOT_FOUND",
        "message": "The specified service does not exist.",
    },
    0x000004DC: {
        "code": "ERROR_NOT_AUTHENTICATED",
        "message": (
            "The operation being requested was not performed because the user has not"
            " been authenticated."
        ),
    },
    0x000004DD: {
        "code": "ERROR_NOT_LOGGED_ON",
        "message": (
            "The operation being requested was not performed because the user has not"
            " logged on to the network. The specified service does not exist."
        ),
    },
    0x000004DE: {
        "code": "ERROR_CONTINUE",
        "message": "Continue with work in progress.",
    },
    0x000004DF: {
        "code": "ERROR_ALREADY_INITIALIZED",
        "message": (
            "An attempt was made to perform an initialization operation when"
            " initialization has already been completed."
        ),
    },
    0x000004E0: {"code": "ERROR_NO_MORE_DEVICES", "message": "No more local devices."},
    0x000004E1: {
        "code": "ERROR_NO_SUCH_SITE",
        "message": "The specified site does not exist.",
    },
    0x000004E2: {
        "code": "ERROR_DOMAIN_CONTROLLER_EXISTS",
        "message": "A domain controller with the specified name already exists.",
    },
    0x000004E3: {
        "code": "ERROR_ONLY_IF_CONNECTED",
        "message": (
            "This operation is supported only when you are connected to the server."
        ),
    },
    0x000004E4: {
        "code": "ERROR_OVERRIDE_NOCHANGES",
        "message": (
            "The group policy framework should call the extension even if there are no"
            " changes."
        ),
    },
    0x000004E5: {
        "code": "ERROR_BAD_USER_PROFILE",
        "message": "The specified user does not have a valid profile.",
    },
    0x000004E6: {
        "code": "ERROR_NOT_SUPPORTED_ON_SBS",
        "message": (
            "This operation is not supported on a computer running Windows Server 2003"
            " operating system for Small Business Server."
        ),
    },
    0x000004E7: {
        "code": "ERROR_SERVER_SHUTDOWN_IN_PROGRESS",
        "message": "The server machine is shutting down.",
    },
    0x000004E8: {
        "code": "ERROR_HOST_DOWN",
        "message": (
            "The remote system is not available. For information about network"
            " troubleshooting, see Windows Help."
        ),
    },
    0x000004E9: {
        "code": "ERROR_NON_ACCOUNT_SID",
        "message": "The security identifier provided is not from an account domain.",
    },
    0x000004EA: {
        "code": "ERROR_NON_DOMAIN_SID",
        "message": "The security identifier provided does not have a domain component.",
    },
    0x000004EB: {
        "code": "ERROR_APPHELP_BLOCK",
        "message": (
            "AppHelp dialog canceled, thus preventing the application from starting."
        ),
    },
    0x000004EC: {
        "code": "ERROR_ACCESS_DISABLED_BY_POLICY",
        "message": (
            "This program is blocked by Group Policy. For more information, contact"
            " your system administrator."
        ),
    },
    0x000004ED: {
        "code": "ERROR_REG_NAT_CONSUMPTION",
        "message": (
            "A program attempt to use an invalid register value. Normally caused by an"
            " uninitialized register. This error is Itanium specific."
        ),
    },
    0x000004EE: {
        "code": "ERROR_CSCSHARE_OFFLINE",
        "message": "The share is currently offline or does not exist.",
    },
    0x000004EF: {
        "code": "ERROR_PKINIT_FAILURE",
        "message": (
            "The Kerberos protocol encountered an error while validating the KDC"
            " certificate during smartcard logon. There is more information in the"
            " system event log."
        ),
    },
    0x000004F0: {
        "code": "ERROR_SMARTCARD_SUBSYSTEM_FAILURE",
        "message": (
            "The Kerberos protocol encountered an error while attempting to utilize the"
            " smartcard subsystem."
        ),
    },
    0x000004F1: {
        "code": "ERROR_DOWNGRADE_DETECTED",
        "message": (
            "The system detected a possible attempt to compromise security. Ensure that"
            " you can contact the server that authenticated you."
        ),
    },
    0x000004F7: {
        "code": "ERROR_MACHINE_LOCKED",
        "message": (
            "The machine is locked and cannot be shut down without the force option."
        ),
    },
    0x000004F9: {
        "code": "ERROR_CALLBACK_SUPPLIED_INVALID_DATA",
        "message": "An application-defined callback gave invalid data when called.",
    },
    0x000004FA: {
        "code": "ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED",
        "message": (
            "The Group Policy framework should call the extension in the synchronous"
            " foreground policy refresh."
        ),
    },
    0x000004FB: {
        "code": "ERROR_DRIVER_BLOCKED",
        "message": "This driver has been blocked from loading.",
    },
    0x000004FC: {
        "code": "ERROR_INVALID_IMPORT_OF_NON_DLL",
        "message": (
            "A DLL referenced a module that was neither a DLL nor the process's"
            " executable image."
        ),
    },
    0x000004FD: {
        "code": "ERROR_ACCESS_DISABLED_WEBBLADE",
        "message": "Windows cannot open this program because it has been disabled.",
    },
    0x000004FE: {
        "code": "ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER",
        "message": (
            "Windows cannot open this program because the license enforcement system"
            " has been tampered with or become corrupted."
        ),
    },
    0x000004FF: {
        "code": "ERROR_RECOVERY_FAILURE",
        "message": "A transaction recover failed.",
    },
    0x00000500: {
        "code": "ERROR_ALREADY_FIBER",
        "message": "The current thread has already been converted to a fiber.",
    },
    0x00000501: {
        "code": "ERROR_ALREADY_THREAD",
        "message": "The current thread has already been converted from a fiber.",
    },
    0x00000502: {
        "code": "ERROR_STACK_BUFFER_OVERRUN",
        "message": (
            "The system detected an overrun of a stack-based buffer in this"
            " application. This overrun could potentially allow a malicious user to"
            " gain control of this application."
        ),
    },
    0x00000503: {
        "code": "ERROR_PARAMETER_QUOTA_EXCEEDED",
        "message": (
            "Data present in one of the parameters is more than the function can"
            " operate on."
        ),
    },
    0x00000504: {
        "code": "ERROR_DEBUGGER_INACTIVE",
        "message": (
            "An attempt to perform an operation on a debug object failed because the"
            " object is in the process of being deleted."
        ),
    },
    0x00000505: {
        "code": "ERROR_DELAY_LOAD_FAILED",
        "message": (
            "An attempt to delay-load a .dll or get a function address in a"
            " delay-loaded .dll failed."
        ),
    },
    0x00000506: {
        "code": "ERROR_VDM_DISALLOWED",
        "message": (
            "%1 is a 16-bit application. You do not have permissions to execute 16-bit"
            " applications. Check your permissions with your system administrator."
        ),
    },
    0x00000507: {
        "code": "ERROR_UNIDENTIFIED_ERROR",
        "message": "Insufficient information exists to identify the cause of failure.",
    },
    0x00000508: {
        "code": "ERROR_INVALID_CRUNTIME_PARAMETER",
        "message": "The parameter passed to a C runtime function is incorrect.",
    },
    0x00000509: {
        "code": "ERROR_BEYOND_VDL",
        "message": "The operation occurred beyond the valid data length of the file.",
    },
    0x0000050A: {
        "code": "ERROR_INCOMPATIBLE_SERVICE_SID_TYPE",
        "message": (
            "The service start failed because one or more services in the same process"
            " have an incompatible service SID type setting. A service with a"
            " restricted service SID type can only coexist in the same process with"
            " other services with a restricted SID type."
        ),
    },
    0x0000050B: {
        "code": "ERROR_DRIVER_PROCESS_TERMINATED",
        "message": (
            "The process hosting the driver for this device has been terminated."
        ),
    },
    0x0000050C: {
        "code": "ERROR_IMPLEMENTATION_LIMIT",
        "message": "An operation attempted to exceed an implementation-defined limit.",
    },
    0x0000050D: {
        "code": "ERROR_PROCESS_IS_PROTECTED",
        "message": (
            "Either the target process, or the target thread's containing process, is a"
            " protected process."
        ),
    },
    0x0000050E: {
        "code": "ERROR_SERVICE_NOTIFY_CLIENT_LAGGING",
        "message": (
            "The service notification client is lagging too far behind the current"
            " state of services in the machine."
        ),
    },
    0x0000050F: {
        "code": "ERROR_DISK_QUOTA_EXCEEDED",
        "message": "An operation failed because the storage quota was exceeded.",
    },
    0x00000510: {
        "code": "ERROR_CONTENT_BLOCKED",
        "message": "An operation failed because the content was blocked.",
    },
    0x00000511: {
        "code": "ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE",
        "message": (
            "A privilege that the service requires to function properly does not exist"
            " in the service account configuration. The Services Microsoft Management"
            " Console (MMC) snap-in (Services.msc) and the Local Security Settings MMC"
            " snap-in (Secpol.msc) can be used to view the service configuration and"
            " the account configuration."
        ),
    },
    0x00000513: {
        "code": "ERROR_INVALID_LABEL",
        "message": (
            "Indicates a particular SID cannot be assigned as the label of an object."
        ),
    },
    0x00000514: {
        "code": "ERROR_NOT_ALL_ASSIGNED",
        "message": (
            "Not all privileges or groups referenced are assigned to the caller."
        ),
    },
    0x00000515: {
        "code": "ERROR_SOME_NOT_MAPPED",
        "message": "Some mapping between account names and SIDs was not done.",
    },
    0x00000516: {
        "code": "ERROR_NO_QUOTAS_FOR_ACCOUNT",
        "message": "No system quota limits are specifically set for this account.",
    },
    0x00000517: {
        "code": "ERROR_LOCAL_USER_SESSION_KEY",
        "message": (
            "No encryption key is available. A well-known encryption key was returned."
        ),
    },
    0x00000518: {
        "code": "ERROR_NULL_LM_PASSWORD",
        "message": (
            "The password is too complex to be converted to a LAN Manager password. The"
            " LAN Manager password returned is a null string."
        ),
    },
    0x00000519: {
        "code": "ERROR_UNKNOWN_REVISION",
        "message": "The revision level is unknown.",
    },
    0x0000051A: {
        "code": "ERROR_REVISION_MISMATCH",
        "message": "Indicates two revision levels are incompatible.",
    },
    0x0000051B: {
        "code": "ERROR_INVALID_OWNER",
        "message": "This SID cannot be assigned as the owner of this object.",
    },
    0x0000051C: {
        "code": "ERROR_INVALID_PRIMARY_GROUP",
        "message": "This SID cannot be assigned as the primary group of an object.",
    },
    0x0000051D: {
        "code": "ERROR_NO_IMPERSONATION_TOKEN",
        "message": (
            "An attempt has been made to operate on an impersonation token by a thread"
            " that is not currently impersonating a client."
        ),
    },
    0x0000051E: {
        "code": "ERROR_CANT_DISABLE_MANDATORY",
        "message": "The group cannot be disabled.",
    },
    0x0000051F: {
        "code": "ERROR_NO_LOGON_SERVERS",
        "message": (
            "There are currently no logon servers available to service the logon"
            " request."
        ),
    },
    0x00000520: {
        "code": "ERROR_NO_SUCH_LOGON_SESSION",
        "message": (
            "A specified logon session does not exist. It might already have been"
            " terminated."
        ),
    },
    0x00000521: {
        "code": "ERROR_NO_SUCH_PRIVILEGE",
        "message": "A specified privilege does not exist.",
    },
    0x00000522: {
        "code": "ERROR_PRIVILEGE_NOT_HELD",
        "message": "A required privilege is not held by the client.",
    },
    0x00000523: {
        "code": "ERROR_INVALID_ACCOUNT_NAME",
        "message": "The name provided is not a properly formed account name.",
    },
    0x00000524: {
        "code": "ERROR_USER_EXISTS",
        "message": "The specified account already exists.",
    },
    0x00000525: {
        "code": "ERROR_NO_SUCH_USER",
        "message": "The specified account does not exist.",
    },
    0x00000526: {
        "code": "ERROR_GROUP_EXISTS",
        "message": "The specified group already exists.",
    },
    0x00000527: {
        "code": "ERROR_NO_SUCH_GROUP",
        "message": "The specified group does not exist.",
    },
    0x00000528: {
        "code": "ERROR_MEMBER_IN_GROUP",
        "message": (
            "Either the specified user account is already a member of the specified"
            " group, or the specified group cannot be deleted because it contains a"
            " member."
        ),
    },
    0x00000529: {
        "code": "ERROR_MEMBER_NOT_IN_GROUP",
        "message": (
            "The specified user account is not a member of the specified group account."
        ),
    },
    0x0000052A: {
        "code": "ERROR_LAST_ADMIN",
        "message": (
            "The last remaining administration account cannot be disabled or deleted."
        ),
    },
    0x0000052B: {
        "code": "ERROR_WRONG_PASSWORD",
        "message": (
            "Unable to update the password. The value provided as the current password"
            " is incorrect."
        ),
    },
    0x0000052C: {
        "code": "ERROR_ILL_FORMED_PASSWORD",
        "message": (
            "Unable to update the password. The value provided for the new password"
            " contains values that are not allowed in passwords."
        ),
    },
    0x0000052D: {
        "code": "ERROR_PASSWORD_RESTRICTION",
        "message": (
            "Unable to update the password. The value provided for the new password"
            " does not meet the length, complexity, or history requirements of the"
            " domain."
        ),
    },
    0x0000052E: {
        "code": "ERROR_LOGON_FAILURE",
        "message": "Logon failure: Unknown user name or bad password.",
    },
    0x0000052F: {
        "code": "ERROR_ACCOUNT_RESTRICTION",
        "message": (
            "Logon failure: User account restriction. Possible reasons are blank"
            " passwords not allowed, logon hour restrictions, or a policy restriction"
            " has been enforced."
        ),
    },
    0x00000530: {
        "code": "ERROR_INVALID_LOGON_HOURS",
        "message": "Logon failure: Account logon time restriction violation.",
    },
    0x00000531: {
        "code": "ERROR_INVALID_WORKSTATION",
        "message": "Logon failure: User not allowed to log on to this computer.",
    },
    0x00000532: {
        "code": "ERROR_PASSWORD_EXPIRED",
        "message": "Logon failure: The specified account password has expired.",
    },
    0x00000533: {
        "code": "ERROR_ACCOUNT_DISABLED",
        "message": "Logon failure: Account currently disabled.",
    },
    0x00000534: {
        "code": "ERROR_NONE_MAPPED",
        "message": "No mapping between account names and SIDs was done.",
    },
    0x00000535: {
        "code": "ERROR_TOO_MANY_LUIDS_REQUESTED",
        "message": (
            "Too many local user identifiers (LUIDs) were requested at one time."
        ),
    },
    0x00000536: {
        "code": "ERROR_LUIDS_EXHAUSTED",
        "message": "No more LUIDs are available.",
    },
    0x00000537: {
        "code": "ERROR_INVALID_SUB_AUTHORITY",
        "message": (
            "The sub-authority part of an SID is invalid for this particular use."
        ),
    },
    0x00000538: {
        "code": "ERROR_INVALID_ACL",
        "message": "The ACL structure is invalid.",
    },
    0x00000539: {
        "code": "ERROR_INVALID_SID",
        "message": "The SID structure is invalid.",
    },
    0x0000053A: {
        "code": "ERROR_INVALID_SECURITY_DESCR",
        "message": "The security descriptor structure is invalid.",
    },
    0x0000053C: {
        "code": "ERROR_BAD_INHERITANCE_ACL",
        "message": "The inherited ACL or ACE could not be built.",
    },
    0x0000053D: {
        "code": "ERROR_SERVER_DISABLED",
        "message": "The server is currently disabled.",
    },
    0x0000053E: {
        "code": "ERROR_SERVER_NOT_DISABLED",
        "message": "The server is currently enabled.",
    },
    0x0000053F: {
        "code": "ERROR_INVALID_ID_AUTHORITY",
        "message": (
            "The value provided was an invalid value for an identifier authority."
        ),
    },
    0x00000540: {
        "code": "ERROR_ALLOTTED_SPACE_EXCEEDED",
        "message": "No more memory is available for security information updates.",
    },
    0x00000541: {
        "code": "ERROR_INVALID_GROUP_ATTRIBUTES",
        "message": (
            "The specified attributes are invalid, or incompatible with the attributes"
            " for the group as a whole."
        ),
    },
    0x00000542: {
        "code": "ERROR_BAD_IMPERSONATION_LEVEL",
        "message": (
            "Either a required impersonation level was not provided, or the provided"
            " impersonation level is invalid."
        ),
    },
    0x00000543: {
        "code": "ERROR_CANT_OPEN_ANONYMOUS",
        "message": "Cannot open an anonymous level security token.",
    },
    0x00000544: {
        "code": "ERROR_BAD_VALIDATION_CLASS",
        "message": "The validation information class requested was invalid.",
    },
    0x00000545: {
        "code": "ERROR_BAD_TOKEN_TYPE",
        "message": "The type of the token is inappropriate for its attempted use.",
    },
    0x00000546: {
        "code": "ERROR_NO_SECURITY_ON_OBJECT",
        "message": (
            "Unable to perform a security operation on an object that has no associated"
            " security."
        ),
    },
    0x00000547: {
        "code": "ERROR_CANT_ACCESS_DOMAIN_INFO",
        "message": (
            "Configuration information could not be read from the domain controller,"
            " either because the machine is unavailable, or access has been denied."
        ),
    },
    0x00000548: {
        "code": "ERROR_INVALID_SERVER_STATE",
        "message": (
            "The SAM or local security authority (LSA) server was in the wrong state to"
            " perform the security operation."
        ),
    },
    0x00000549: {
        "code": "ERROR_INVALID_DOMAIN_STATE",
        "message": (
            "The domain was in the wrong state to perform the security operation."
        ),
    },
    0x0000054A: {
        "code": "ERROR_INVALID_DOMAIN_ROLE",
        "message": "This operation is only allowed for the PDC of the domain.",
    },
    0x0000054B: {
        "code": "ERROR_NO_SUCH_DOMAIN",
        "message": (
            "The specified domain either does not exist or could not be contacted."
        ),
    },
    0x0000054C: {
        "code": "ERROR_DOMAIN_EXISTS",
        "message": "The specified domain already exists.",
    },
    0x0000054D: {
        "code": "ERROR_DOMAIN_LIMIT_EXCEEDED",
        "message": (
            "An attempt was made to exceed the limit on the number of domains per"
            " server."
        ),
    },
    0x0000054E: {
        "code": "ERROR_INTERNAL_DB_CORRUPTION",
        "message": (
            "Unable to complete the requested operation because of either a"
            " catastrophic media failure or a data structure corruption on the disk."
        ),
    },
    0x0000054F: {
        "code": "ERROR_INTERNAL_ERROR",
        "message": "An internal error occurred.",
    },
    0x00000550: {
        "code": "ERROR_GENERIC_NOT_MAPPED",
        "message": (
            "Generic access types were contained in an access mask that should already"
            " be mapped to nongeneric types."
        ),
    },
    0x00000551: {
        "code": "ERROR_BAD_DESCRIPTOR_FORMAT",
        "message": (
            "A security descriptor is not in the right format (absolute or"
            " self-relative)."
        ),
    },
    0x00000552: {
        "code": "ERROR_NOT_LOGON_PROCESS",
        "message": (
            "The requested action is restricted for use by logon processes only. The"
            " calling process has not registered as a logon process."
        ),
    },
    0x00000553: {
        "code": "ERROR_LOGON_SESSION_EXISTS",
        "message": (
            "Cannot start a new logon session with an ID that is already in use."
        ),
    },
    0x00000554: {
        "code": "ERROR_NO_SUCH_PACKAGE",
        "message": "A specified authentication package is unknown.",
    },
    0x00000555: {
        "code": "ERROR_BAD_LOGON_SESSION_STATE",
        "message": (
            "The logon session is not in a state that is consistent with the requested"
            " operation."
        ),
    },
    0x00000556: {
        "code": "ERROR_LOGON_SESSION_COLLISION",
        "message": "The logon session ID is already in use.",
    },
    0x00000557: {
        "code": "ERROR_INVALID_LOGON_TYPE",
        "message": "A logon request contained an invalid logon type value.",
    },
    0x00000558: {
        "code": "ERROR_CANNOT_IMPERSONATE",
        "message": (
            "Unable to impersonate using a named pipe until data has been read from"
            " that pipe."
        ),
    },
    0x00000559: {
        "code": "ERROR_RXACT_INVALID_STATE",
        "message": (
            "The transaction state of a registry subtree is incompatible with the"
            " requested operation."
        ),
    },
    0x0000055A: {
        "code": "ERROR_RXACT_COMMIT_FAILURE",
        "message": "An internal security database corruption has been encountered.",
    },
    0x0000055B: {
        "code": "ERROR_SPECIAL_ACCOUNT",
        "message": "Cannot perform this operation on built-in accounts.",
    },
    0x0000055C: {
        "code": "ERROR_SPECIAL_GROUP",
        "message": "Cannot perform this operation on this built-in special group.",
    },
    0x0000055D: {
        "code": "ERROR_SPECIAL_USER",
        "message": "Cannot perform this operation on this built-in special user.",
    },
    0x0000055E: {
        "code": "ERROR_MEMBERS_PRIMARY_GROUP",
        "message": (
            "The user cannot be removed from a group because the group is currently the"
            " user's primary group."
        ),
    },
    0x0000055F: {
        "code": "ERROR_TOKEN_ALREADY_IN_USE",
        "message": "The token is already in use as a primary token.",
    },
    0x00000560: {
        "code": "ERROR_NO_SUCH_ALIAS",
        "message": "The specified local group does not exist.",
    },
    0x00000561: {
        "code": "ERROR_MEMBER_NOT_IN_ALIAS",
        "message": "The specified account name is not a member of the group.",
    },
    0x00000562: {
        "code": "ERROR_MEMBER_IN_ALIAS",
        "message": "The specified account name is already a member of the group.",
    },
    0x00000563: {
        "code": "ERROR_ALIAS_EXISTS",
        "message": "The specified local group already exists.",
    },
    0x00000564: {
        "code": "ERROR_LOGON_NOT_GRANTED",
        "message": (
            "Logon failure: The user has not been granted the requested logon type at"
            " this computer."
        ),
    },
    0x00000565: {
        "code": "ERROR_TOO_MANY_SECRETS",
        "message": (
            "The maximum number of secrets that can be stored in a single system has"
            " been exceeded."
        ),
    },
    0x00000566: {
        "code": "ERROR_SECRET_TOO_LONG",
        "message": "The length of a secret exceeds the maximum length allowed.",
    },
    0x00000567: {
        "code": "ERROR_INTERNAL_DB_ERROR",
        "message": (
            "The local security authority database contains an internal inconsistency."
        ),
    },
    0x00000568: {
        "code": "ERROR_TOO_MANY_CONTEXT_IDS",
        "message": (
            "During a logon attempt, the user's security context accumulated too many"
            " SIDs."
        ),
    },
    0x00000569: {
        "code": "ERROR_LOGON_TYPE_NOT_GRANTED",
        "message": (
            "Logon failure: The user has not been granted the requested logon type at"
            " this computer."
        ),
    },
    0x0000056A: {
        "code": "ERROR_NT_CROSS_ENCRYPTION_REQUIRED",
        "message": "A cross-encrypted password is necessary to change a user password.",
    },
    0x0000056B: {
        "code": "ERROR_NO_SUCH_MEMBER",
        "message": (
            "A member could not be added to or removed from the local group because the"
            " member does not exist."
        ),
    },
    0x0000056C: {
        "code": "ERROR_INVALID_MEMBER",
        "message": (
            "A new member could not be added to a local group because the member has"
            " the wrong account type."
        ),
    },
    0x0000056D: {
        "code": "ERROR_TOO_MANY_SIDS",
        "message": "Too many SIDs have been specified.",
    },
    0x0000056E: {
        "code": "ERROR_LM_CROSS_ENCRYPTION_REQUIRED",
        "message": (
            "A cross-encrypted password is necessary to change this user password."
        ),
    },
    0x0000056F: {
        "code": "ERROR_NO_INHERITANCE",
        "message": "Indicates an ACL contains no inheritable components.",
    },
    0x00000570: {
        "code": "ERROR_FILE_CORRUPT",
        "message": "The file or directory is corrupted and unreadable.",
    },
    0x00000571: {
        "code": "ERROR_DISK_CORRUPT",
        "message": "The disk structure is corrupted and unreadable.",
    },
    0x00000572: {
        "code": "ERROR_NO_USER_SESSION_KEY",
        "message": "There is no user session key for the specified logon session.",
    },
    0x00000573: {
        "code": "ERROR_LICENSE_QUOTA_EXCEEDED",
        "message": (
            "The service being accessed is licensed for a particular number of"
            " connections. No more connections can be made to the service at this time"
            " because the service has accepted the maximum number of connections."
        ),
    },
    0x00000574: {
        "code": "ERROR_WRONG_TARGET_NAME",
        "message": "Logon failure: The target account name is incorrect.",
    },
    0x00000575: {
        "code": "ERROR_MUTUAL_AUTH_FAILED",
        "message": (
            "Mutual authentication failed. The server's password is out of date at the"
            " domain controller."
        ),
    },
    0x00000576: {
        "code": "ERROR_TIME_SKEW",
        "message": (
            "There is a time and/or date difference between the client and server."
        ),
    },
    0x00000577: {
        "code": "ERROR_CURRENT_DOMAIN_NOT_ALLOWED",
        "message": "This operation cannot be performed on the current domain.",
    },
    0x00000578: {
        "code": "ERROR_INVALID_WINDOW_HANDLE",
        "message": "Invalid window handle.",
    },
    0x00000579: {
        "code": "ERROR_INVALID_MENU_HANDLE",
        "message": "Invalid menu handle.",
    },
    0x0000057A: {
        "code": "ERROR_INVALID_CURSOR_HANDLE",
        "message": "Invalid cursor handle.",
    },
    0x0000057B: {
        "code": "ERROR_INVALID_ACCEL_HANDLE",
        "message": "Invalid accelerator table handle.",
    },
    0x0000057C: {
        "code": "ERROR_INVALID_HOOK_HANDLE",
        "message": "Invalid hook handle.",
    },
    0x0000057D: {
        "code": "ERROR_INVALID_DWP_HANDLE",
        "message": "Invalid handle to a multiple-window position structure.",
    },
    0x0000057E: {
        "code": "ERROR_TLW_WITH_WSCHILD",
        "message": "Cannot create a top-level child window.",
    },
    0x0000057F: {
        "code": "ERROR_CANNOT_FIND_WND_CLASS",
        "message": "Cannot find window class.",
    },
    0x00000580: {
        "code": "ERROR_WINDOW_OF_OTHER_THREAD",
        "message": "Invalid window; it belongs to other thread.",
    },
    0x00000581: {
        "code": "ERROR_HOTKEY_ALREADY_REGISTERED",
        "message": "Hot key is already registered.",
    },
    0x00000582: {
        "code": "ERROR_CLASS_ALREADY_EXISTS",
        "message": "Class already exists.",
    },
    0x00000583: {
        "code": "ERROR_CLASS_DOES_NOT_EXIST",
        "message": "Class does not exist.",
    },
    0x00000584: {
        "code": "ERROR_CLASS_HAS_WINDOWS",
        "message": "Class still has open windows.",
    },
    0x00000585: {"code": "ERROR_INVALID_INDEX", "message": "Invalid index."},
    0x00000586: {
        "code": "ERROR_INVALID_ICON_HANDLE",
        "message": "Invalid icon handle.",
    },
    0x00000587: {
        "code": "ERROR_PRIVATE_DIALOG_INDEX",
        "message": "Using private DIALOG window words.",
    },
    0x00000588: {
        "code": "ERROR_LISTBOX_ID_NOT_FOUND",
        "message": "The list box identifier was not found.",
    },
    0x00000589: {
        "code": "ERROR_NO_WILDCARD_CHARACTERS",
        "message": "No wildcards were found.",
    },
    0x0000058A: {
        "code": "ERROR_CLIPBOARD_NOT_OPEN",
        "message": "Thread does not have a clipboard open.",
    },
    0x0000058B: {
        "code": "ERROR_HOTKEY_NOT_REGISTERED",
        "message": "Hot key is not registered.",
    },
    0x0000058C: {
        "code": "ERROR_WINDOW_NOT_DIALOG",
        "message": "The window is not a valid dialog window.",
    },
    0x0000058D: {
        "code": "ERROR_CONTROL_ID_NOT_FOUND",
        "message": "Control ID not found.",
    },
    0x0000058E: {
        "code": "ERROR_INVALID_COMBOBOX_MESSAGE",
        "message": (
            "Invalid message for a combo box because it does not have an edit control."
        ),
    },
    0x0000058F: {
        "code": "ERROR_WINDOW_NOT_COMBOBOX",
        "message": "The window is not a combo box.",
    },
    0x00000590: {
        "code": "ERROR_INVALID_EDIT_HEIGHT",
        "message": "Height must be less than 256.",
    },
    0x00000591: {
        "code": "ERROR_DC_NOT_FOUND",
        "message": "Invalid device context (DC) handle.",
    },
    0x00000592: {
        "code": "ERROR_INVALID_HOOK_FILTER",
        "message": "Invalid hook procedure type.",
    },
    0x00000593: {
        "code": "ERROR_INVALID_FILTER_PROC",
        "message": "Invalid hook procedure.",
    },
    0x00000594: {
        "code": "ERROR_HOOK_NEEDS_HMOD",
        "message": "Cannot set nonlocal hook without a module handle.",
    },
    0x00000595: {
        "code": "ERROR_GLOBAL_ONLY_HOOK",
        "message": "This hook procedure can only be set globally.",
    },
    0x00000596: {
        "code": "ERROR_JOURNAL_HOOK_SET",
        "message": "The journal hook procedure is already installed.",
    },
    0x00000597: {
        "code": "ERROR_HOOK_NOT_INSTALLED",
        "message": "The hook procedure is not installed.",
    },
    0x00000598: {
        "code": "ERROR_INVALID_LB_MESSAGE",
        "message": "Invalid message for single-selection list box.",
    },
    0x00000599: {
        "code": "ERROR_SETCOUNT_ON_BAD_LB",
        "message": "LB_SETCOUNT sent to non-lazy list box.",
    },
    0x0000059A: {
        "code": "ERROR_LB_WITHOUT_TABSTOPS",
        "message": "This list box does not support tab stops.",
    },
    0x0000059B: {
        "code": "ERROR_DESTROY_OBJECT_OF_OTHER_THREAD",
        "message": "Cannot destroy object created by another thread.",
    },
    0x0000059C: {
        "code": "ERROR_CHILD_WINDOW_MENU",
        "message": "Child windows cannot have menus.",
    },
    0x0000059D: {
        "code": "ERROR_NO_SYSTEM_MENU",
        "message": "The window does not have a system menu.",
    },
    0x0000059E: {
        "code": "ERROR_INVALID_MSGBOX_STYLE",
        "message": "Invalid message box style.",
    },
    0x0000059F: {
        "code": "ERROR_INVALID_SPI_VALUE",
        "message": "Invalid system-wide (SPI_*) parameter.",
    },
    0x000005A0: {
        "code": "ERROR_SCREEN_ALREADY_LOCKED",
        "message": "Screen already locked.",
    },
    0x000005A1: {
        "code": "ERROR_HWNDS_HAVE_DIFF_PARENT",
        "message": (
            "All handles to windows in a multiple-window position structure must have"
            " the same parent."
        ),
    },
    0x000005A2: {
        "code": "ERROR_NOT_CHILD_WINDOW",
        "message": "The window is not a child window.",
    },
    0x000005A3: {
        "code": "ERROR_INVALID_GW_COMMAND",
        "message": "Invalid GW_* command.",
    },
    0x000005A4: {
        "code": "ERROR_INVALID_THREAD_ID",
        "message": "Invalid thread identifier.",
    },
    0x000005A5: {
        "code": "ERROR_NON_MDICHILD_WINDOW",
        "message": (
            "Cannot process a message from a window that is not a multiple document"
            " interface (MDI) window."
        ),
    },
    0x000005A6: {
        "code": "ERROR_POPUP_ALREADY_ACTIVE",
        "message": "Pop-up menu already active.",
    },
    0x000005A7: {
        "code": "ERROR_NO_SCROLLBARS",
        "message": "The window does not have scroll bars.",
    },
    0x000005A8: {
        "code": "ERROR_INVALID_SCROLLBAR_RANGE",
        "message": "Scroll bar range cannot be greater than MAXLONG.",
    },
    0x000005A9: {
        "code": "ERROR_INVALID_SHOWWIN_COMMAND",
        "message": "Cannot show or remove the window in the way specified.",
    },
    0x000005AA: {
        "code": "ERROR_NO_SYSTEM_RESOURCES",
        "message": (
            "Insufficient system resources exist to complete the requested service."
        ),
    },
    0x000005AB: {
        "code": "ERROR_NONPAGED_SYSTEM_RESOURCES",
        "message": (
            "Insufficient system resources exist to complete the requested service."
        ),
    },
    0x000005AC: {
        "code": "ERROR_PAGED_SYSTEM_RESOURCES",
        "message": (
            "Insufficient system resources exist to complete the requested service."
        ),
    },
    0x000005AD: {
        "code": "ERROR_WORKING_SET_QUOTA",
        "message": "Insufficient quota to complete the requested service.",
    },
    0x000005AE: {
        "code": "ERROR_PAGEFILE_QUOTA",
        "message": "Insufficient quota to complete the requested service.",
    },
    0x000005AF: {
        "code": "ERROR_COMMITMENT_LIMIT",
        "message": "The paging file is too small for this operation to complete.",
    },
    0x000005B0: {
        "code": "ERROR_MENU_ITEM_NOT_FOUND",
        "message": "A menu item was not found.",
    },
    0x000005B1: {
        "code": "ERROR_INVALID_KEYBOARD_HANDLE",
        "message": "Invalid keyboard layout handle.",
    },
    0x000005B2: {
        "code": "ERROR_HOOK_TYPE_NOT_ALLOWED",
        "message": "Hook type not allowed.",
    },
    0x000005B3: {
        "code": "ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION",
        "message": "This operation requires an interactive window station.",
    },
    0x000005B4: {
        "code": "ERROR_TIMEOUT",
        "message": "This operation returned because the time-out period expired.",
    },
    0x000005B5: {
        "code": "ERROR_INVALID_MONITOR_HANDLE",
        "message": "Invalid monitor handle.",
    },
    0x000005B6: {"code": "ERROR_INCORRECT_SIZE", "message": "Incorrect size argument."},
    0x000005B7: {
        "code": "ERROR_SYMLINK_CLASS_DISABLED",
        "message": "The symbolic link cannot be followed because its type is disabled.",
    },
    0x000005B8: {
        "code": "ERROR_SYMLINK_NOT_SUPPORTED",
        "message": (
            "This application does not support the current operation on symbolic links."
        ),
    },
    0x000005DC: {
        "code": "ERROR_EVENTLOG_FILE_CORRUPT",
        "message": "The event log file is corrupted.",
    },
    0x000005DD: {
        "code": "ERROR_EVENTLOG_CANT_START",
        "message": (
            "No event log file could be opened, so the event logging service did not"
            " start."
        ),
    },
    0x000005DE: {
        "code": "ERROR_LOG_FILE_FULL",
        "message": "The event log file is full.",
    },
    0x000005DF: {
        "code": "ERROR_EVENTLOG_FILE_CHANGED",
        "message": "The event log file has changed between read operations.",
    },
    0x0000060E: {
        "code": "ERROR_INVALID_TASK_NAME",
        "message": "The specified task name is invalid.",
    },
    0x0000060F: {
        "code": "ERROR_INVALID_TASK_INDEX",
        "message": "The specified task index is invalid.",
    },
    0x00000610: {
        "code": "ERROR_THREAD_ALREADY_IN_TASK",
        "message": "The specified thread is already joining a task.",
    },
    0x00000641: {
        "code": "ERROR_INSTALL_SERVICE_FAILURE",
        "message": (
            "The Windows Installer service could not be accessed. This can occur if the"
            " Windows Installer is not correctly installed. Contact your support"
            " personnel for assistance."
        ),
    },
    0x00000642: {
        "code": "ERROR_INSTALL_USEREXIT",
        "message": "User canceled installation.",
    },
    0x00000643: {
        "code": "ERROR_INSTALL_FAILURE",
        "message": "Fatal error during installation.",
    },
    0x00000644: {
        "code": "ERROR_INSTALL_SUSPEND",
        "message": "Installation suspended, incomplete.",
    },
    0x00000645: {
        "code": "ERROR_UNKNOWN_PRODUCT",
        "message": (
            "This action is valid only for products that are currently installed."
        ),
    },
    0x00000646: {
        "code": "ERROR_UNKNOWN_FEATURE",
        "message": "Feature ID not registered.",
    },
    0x00000647: {
        "code": "ERROR_UNKNOWN_COMPONENT",
        "message": "Component ID not registered.",
    },
    0x00000648: {"code": "ERROR_UNKNOWN_PROPERTY", "message": "Unknown property."},
    0x00000649: {
        "code": "ERROR_INVALID_HANDLE_STATE",
        "message": "Handle is in an invalid state.",
    },
    0x0000064A: {
        "code": "ERROR_BAD_CONFIGURATION",
        "message": (
            "The configuration data for this product is corrupt. Contact your support"
            " personnel."
        ),
    },
    0x0000064B: {
        "code": "ERROR_INDEX_ABSENT",
        "message": "Component qualifier not present.",
    },
    0x0000064C: {
        "code": "ERROR_INSTALL_SOURCE_ABSENT",
        "message": (
            "The installation source for this product is not available. Verify that the"
            " source exists and that you can access it."
        ),
    },
    0x0000064D: {
        "code": "ERROR_INSTALL_PACKAGE_VERSION",
        "message": (
            "This installation package cannot be installed by the Windows Installer"
            " service. You must install a Windows service pack that contains a newer"
            " version of the Windows Installer service."
        ),
    },
    0x0000064E: {
        "code": "ERROR_PRODUCT_UNINSTALLED",
        "message": "Product is uninstalled.",
    },
    0x0000064F: {
        "code": "ERROR_BAD_QUERY_SYNTAX",
        "message": "SQL query syntax invalid or unsupported.",
    },
    0x00000650: {
        "code": "ERROR_INVALID_FIELD",
        "message": "Record field does not exist.",
    },
    0x00000651: {
        "code": "ERROR_DEVICE_REMOVED",
        "message": "The device has been removed.",
    },
    0x00000652: {
        "code": "ERROR_INSTALL_ALREADY_RUNNING",
        "message": (
            "Another installation is already in progress. Complete that installation"
            " before proceeding with this install."
        ),
    },
    0x00000653: {
        "code": "ERROR_INSTALL_PACKAGE_OPEN_FAILED",
        "message": (
            "This installation package could not be opened. Verify that the package"
            " exists and that you can access it, or contact the application vendor to"
            " verify that this is a valid Windows Installer package."
        ),
    },
    0x00000654: {
        "code": "ERROR_INSTALL_PACKAGE_INVALID",
        "message": (
            "This installation package could not be opened. Contact the application"
            " vendor to verify that this is a valid Windows Installer package."
        ),
    },
    0x00000655: {
        "code": "ERROR_INSTALL_UI_FAILURE",
        "message": (
            "There was an error starting the Windows Installer service user interface."
            " Contact your support personnel."
        ),
    },
    0x00000656: {
        "code": "ERROR_INSTALL_LOG_FAILURE",
        "message": (
            "Error opening installation log file. Verify that the specified log file"
            " location exists and that you can write to it."
        ),
    },
    0x00000657: {
        "code": "ERROR_INSTALL_LANGUAGE_UNSUPPORTED",
        "message": (
            "The language of this installation package is not supported by your system."
        ),
    },
    0x00000658: {
        "code": "ERROR_INSTALL_TRANSFORM_FAILURE",
        "message": (
            "Error applying transforms. Verify that the specified transform paths are"
            " valid."
        ),
    },
    0x00000659: {
        "code": "ERROR_INSTALL_PACKAGE_REJECTED",
        "message": (
            "This installation is forbidden by system policy. Contact your system"
            " administrator."
        ),
    },
    0x0000065A: {
        "code": "ERROR_FUNCTION_NOT_CALLED",
        "message": "Function could not be executed.",
    },
    0x0000065B: {
        "code": "ERROR_FUNCTION_FAILED",
        "message": "Function failed during execution.",
    },
    0x0000065C: {
        "code": "ERROR_INVALID_TABLE",
        "message": "Invalid or unknown table specified.",
    },
    0x0000065D: {
        "code": "ERROR_DATATYPE_MISMATCH",
        "message": "Data supplied is of wrong type.",
    },
    0x0000065E: {
        "code": "ERROR_UNSUPPORTED_TYPE",
        "message": "Data of this type is not supported.",
    },
    0x0000065F: {
        "code": "ERROR_CREATE_FAILED",
        "message": (
            "The Windows Installer service failed to start. Contact your support"
            " personnel."
        ),
    },
    0x00000660: {
        "code": "ERROR_INSTALL_TEMP_UNWRITABLE",
        "message": (
            "The Temp folder is on a drive that is full or is inaccessible. Free up"
            " space on the drive or verify that you have write permission on the Temp"
            " folder."
        ),
    },
    0x00000661: {
        "code": "ERROR_INSTALL_PLATFORM_UNSUPPORTED",
        "message": (
            "This installation package is not supported by this processor type. Contact"
            " your product vendor."
        ),
    },
    0x00000662: {
        "code": "ERROR_INSTALL_NOTUSED",
        "message": "Component not used on this computer.",
    },
    0x00000663: {
        "code": "ERROR_PATCH_PACKAGE_OPEN_FAILED",
        "message": (
            "This update package could not be opened. Verify that the update package"
            " exists and that you can access it, or contact the application vendor to"
            " verify that this is a valid Windows Installer update package."
        ),
    },
    0x00000664: {
        "code": "ERROR_PATCH_PACKAGE_INVALID",
        "message": (
            "This update package could not be opened. Contact the application vendor to"
            " verify that this is a valid Windows Installer update package."
        ),
    },
    0x00000665: {
        "code": "ERROR_PATCH_PACKAGE_UNSUPPORTED",
        "message": (
            "This update package cannot be processed by the Windows Installer service."
            " You must install a Windows service pack that contains a newer version of"
            " the Windows Installer service."
        ),
    },
    0x00000666: {
        "code": "ERROR_PRODUCT_VERSION",
        "message": (
            "Another version of this product is already installed. Installation of this"
            " version cannot continue. To configure or remove the existing version of"
            " this product, use Add/Remove Programs in Control Panel."
        ),
    },
    0x00000667: {
        "code": "ERROR_INVALID_COMMAND_LINE",
        "message": (
            "Invalid command-line argument. Consult the Windows Installer SDK for"
            " detailed command line help."
        ),
    },
    0x00000668: {
        "code": "ERROR_INSTALL_REMOTE_DISALLOWED",
        "message": (
            "Only administrators have permission to add, remove, or configure server"
            " software during a Terminal Services remote session. If you want to"
            " install or configure software on the server, contact your network"
            " administrator."
        ),
    },
    0x00000669: {
        "code": "ERROR_SUCCESS_REBOOT_INITIATED",
        "message": (
            "The requested operation completed successfully. The system will be"
            " restarted so the changes can take effect."
        ),
    },
    0x0000066A: {
        "code": "ERROR_PATCH_TARGET_NOT_FOUND",
        "message": (
            "The upgrade cannot be installed by the Windows Installer service because"
            " the program to be upgraded might be missing, or the upgrade might update"
            " a different version of the program. Verify that the program to be"
            " upgraded exists on your computer and that you have the correct upgrade."
        ),
    },
    0x0000066B: {
        "code": "ERROR_PATCH_PACKAGE_REJECTED",
        "message": (
            "The update package is not permitted by a software restriction policy."
        ),
    },
    0x0000066C: {
        "code": "ERROR_INSTALL_TRANSFORM_REJECTED",
        "message": (
            "One or more customizations are not permitted by a software restriction"
            " policy."
        ),
    },
    0x0000066D: {
        "code": "ERROR_INSTALL_REMOTE_PROHIBITED",
        "message": (
            "The Windows Installer does not permit installation from a Remote Desktop"
            " Connection."
        ),
    },
    0x0000066E: {
        "code": "ERROR_PATCH_REMOVAL_UNSUPPORTED",
        "message": "Uninstallation of the update package is not supported.",
    },
    0x0000066F: {
        "code": "ERROR_UNKNOWN_PATCH",
        "message": "The update is not applied to this product.",
    },
    0x00000670: {
        "code": "ERROR_PATCH_NO_SEQUENCE",
        "message": "No valid sequence could be found for the set of updates.",
    },
    0x00000671: {
        "code": "ERROR_PATCH_REMOVAL_DISALLOWED",
        "message": "Update removal was disallowed by policy.",
    },
    0x00000672: {
        "code": "ERROR_INVALID_PATCH_XML",
        "message": "The XML update data is invalid.",
    },
    0x00000673: {
        "code": "ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT",
        "message": (
            "Windows Installer does not permit updating of managed advertised products."
            " At least one feature of the product must be installed before applying the"
            " update."
        ),
    },
    0x00000674: {
        "code": "ERROR_INSTALL_SERVICE_SAFEBOOT",
        "message": (
            "The Windows Installer service is not accessible in Safe Mode. Try again"
            " when your computer is not in Safe Mode or you can use System Restore to"
            " return your machine to a previous good state."
        ),
    },
    0x000006A4: {
        "code": "RPC_S_INVALID_STRING_BINDING",
        "message": "The string binding is invalid.",
    },
    0x000006A5: {
        "code": "RPC_S_WRONG_KIND_OF_BINDING",
        "message": "The binding handle is not the correct type.",
    },
    0x000006A6: {
        "code": "RPC_S_INVALID_BINDING",
        "message": "The binding handle is invalid.",
    },
    0x000006A7: {
        "code": "RPC_S_PROTSEQ_NOT_SUPPORTED",
        "message": "The RPC protocol sequence is not supported.",
    },
    0x000006A8: {
        "code": "RPC_S_INVALID_RPC_PROTSEQ",
        "message": "The RPC protocol sequence is invalid.",
    },
    0x000006A9: {
        "code": "RPC_S_INVALID_STRING_UUID",
        "message": "The string UUID is invalid.",
    },
    0x000006AA: {
        "code": "RPC_S_INVALID_ENDPOINT_FORMAT",
        "message": "The endpoint format is invalid.",
    },
    0x000006AB: {
        "code": "RPC_S_INVALID_NET_ADDR",
        "message": "The network address is invalid.",
    },
    0x000006AC: {
        "code": "RPC_S_NO_ENDPOINT_FOUND",
        "message": "No endpoint was found.",
    },
    0x000006AD: {
        "code": "RPC_S_INVALID_TIMEOUT",
        "message": "The time-out value is invalid.",
    },
    0x000006AE: {
        "code": "RPC_S_OBJECT_NOT_FOUND",
        "message": "The object UUID) was not found.",
    },
    0x000006AF: {
        "code": "RPC_S_ALREADY_REGISTERED",
        "message": "The object UUID) has already been registered.",
    },
    0x000006B0: {
        "code": "RPC_S_TYPE_ALREADY_REGISTERED",
        "message": "The type UUID has already been registered.",
    },
    0x000006B1: {
        "code": "RPC_S_ALREADY_LISTENING",
        "message": "The RPC server is already listening.",
    },
    0x000006B2: {
        "code": "RPC_S_NO_PROTSEQS_REGISTERED",
        "message": "No protocol sequences have been registered.",
    },
    0x000006B3: {
        "code": "RPC_S_NOT_LISTENING",
        "message": "The RPC server is not listening.",
    },
    0x000006B4: {
        "code": "RPC_S_UNKNOWN_MGR_TYPE",
        "message": "The manager type is unknown.",
    },
    0x000006B5: {"code": "RPC_S_UNKNOWN_IF", "message": "The interface is unknown."},
    0x000006B6: {"code": "RPC_S_NO_BINDINGS", "message": "There are no bindings."},
    0x000006B7: {
        "code": "RPC_S_NO_PROTSEQS",
        "message": "There are no protocol sequences.",
    },
    0x000006B8: {
        "code": "RPC_S_CANT_CREATE_ENDPOINT",
        "message": "The endpoint cannot be created.",
    },
    0x000006B9: {
        "code": "RPC_S_OUT_OF_RESOURCES",
        "message": "Not enough resources are available to complete this operation.",
    },
    0x000006BA: {
        "code": "RPC_S_SERVER_UNAVAILABLE",
        "message": "The RPC server is unavailable.",
    },
    0x000006BB: {
        "code": "RPC_S_SERVER_TOO_BUSY",
        "message": "The RPC server is too busy to complete this operation.",
    },
    0x000006BC: {
        "code": "RPC_S_INVALID_NETWORK_OPTIONS",
        "message": "The network options are invalid.",
    },
    0x000006BD: {
        "code": "RPC_S_NO_CALL_ACTIVE",
        "message": "There are no RPCs active on this thread.",
    },
    0x000006BE: {"code": "RPC_S_CALL_FAILED", "message": "The RPC failed."},
    0x000006BF: {
        "code": "RPC_S_CALL_FAILED_DNE",
        "message": "The RPC failed and did not execute.",
    },
    0x000006C0: {
        "code": "RPC_S_PROTOCOL_ERROR",
        "message": "An RPC protocol error occurred.",
    },
    0x000006C1: {
        "code": "RPC_S_PROXY_ACCESS_DENIED",
        "message": "Access to the HTTP proxy is denied.",
    },
    0x000006C2: {
        "code": "RPC_S_UNSUPPORTED_TRANS_SYN",
        "message": "The transfer syntax is not supported by the RPC server.",
    },
    0x000006C4: {
        "code": "RPC_S_UNSUPPORTED_TYPE",
        "message": "The UUID type is not supported.",
    },
    0x000006C5: {"code": "RPC_S_INVALID_TAG", "message": "The tag is invalid."},
    0x000006C6: {
        "code": "RPC_S_INVALID_BOUND",
        "message": "The array bounds are invalid.",
    },
    0x000006C7: {
        "code": "RPC_S_NO_ENTRY_NAME",
        "message": "The binding does not contain an entry name.",
    },
    0x000006C8: {
        "code": "RPC_S_INVALID_NAME_SYNTAX",
        "message": "The name syntax is invalid.",
    },
    0x000006C9: {
        "code": "RPC_S_UNSUPPORTED_NAME_SYNTAX",
        "message": "The name syntax is not supported.",
    },
    0x000006CB: {
        "code": "RPC_S_UUID_NO_ADDRESS",
        "message": "No network address is available to use to construct a UUID.",
    },
    0x000006CC: {
        "code": "RPC_S_DUPLICATE_ENDPOINT",
        "message": "The endpoint is a duplicate.",
    },
    0x000006CD: {
        "code": "RPC_S_UNKNOWN_AUTHN_TYPE",
        "message": "The authentication type is unknown.",
    },
    0x000006CE: {
        "code": "RPC_S_MAX_CALLS_TOO_SMALL",
        "message": "The maximum number of calls is too small.",
    },
    0x000006CF: {"code": "RPC_S_STRING_TOO_LONG", "message": "The string is too long."},
    0x000006D0: {
        "code": "RPC_S_PROTSEQ_NOT_FOUND",
        "message": "The RPC protocol sequence was not found.",
    },
    0x000006D1: {
        "code": "RPC_S_PROCNUM_OUT_OF_RANGE",
        "message": "The procedure number is out of range.",
    },
    0x000006D2: {
        "code": "RPC_S_BINDING_HAS_NO_AUTH",
        "message": "The binding does not contain any authentication information.",
    },
    0x000006D3: {
        "code": "RPC_S_UNKNOWN_AUTHN_SERVICE",
        "message": "The authentication service is unknown.",
    },
    0x000006D4: {
        "code": "RPC_S_UNKNOWN_AUTHN_LEVEL",
        "message": "The authentication level is unknown.",
    },
    0x000006D5: {
        "code": "RPC_S_INVALID_AUTH_IDENTITY",
        "message": "The security context is invalid.",
    },
    0x000006D6: {
        "code": "RPC_S_UNKNOWN_AUTHZ_SERVICE",
        "message": "The authorization service is unknown.",
    },
    0x000006D7: {"code": "EPT_S_INVALID_ENTRY", "message": "The entry is invalid."},
    0x000006D8: {
        "code": "EPT_S_CANT_PERFORM_OP",
        "message": "The server endpoint cannot perform the operation.",
    },
    0x000006D9: {
        "code": "EPT_S_NOT_REGISTERED",
        "message": "There are no more endpoints available from the endpoint mapper.",
    },
    0x000006DA: {
        "code": "RPC_S_NOTHING_TO_EXPORT",
        "message": "No interfaces have been exported.",
    },
    0x000006DB: {
        "code": "RPC_S_INCOMPLETE_NAME",
        "message": "The entry name is incomplete.",
    },
    0x000006DC: {
        "code": "RPC_S_INVALID_VERS_OPTION",
        "message": "The version option is invalid.",
    },
    0x000006DD: {
        "code": "RPC_S_NO_MORE_MEMBERS",
        "message": "There are no more members.",
    },
    0x000006DE: {
        "code": "RPC_S_NOT_ALL_OBJS_UNEXPORTED",
        "message": "There is nothing to unexport.",
    },
    0x000006DF: {
        "code": "RPC_S_INTERFACE_NOT_FOUND",
        "message": "The interface was not found.",
    },
    0x000006E0: {
        "code": "RPC_S_ENTRY_ALREADY_EXISTS",
        "message": "The entry already exists.",
    },
    0x000006E1: {"code": "RPC_S_ENTRY_NOT_FOUND", "message": "The entry is not found."},
    0x000006E2: {
        "code": "RPC_S_NAME_SERVICE_UNAVAILABLE",
        "message": "The name service is unavailable.",
    },
    0x000006E3: {
        "code": "RPC_S_INVALID_NAF_ID",
        "message": "The network address family is invalid.",
    },
    0x000006E4: {
        "code": "RPC_S_CANNOT_SUPPORT",
        "message": "The requested operation is not supported.",
    },
    0x000006E5: {
        "code": "RPC_S_NO_CONTEXT_AVAILABLE",
        "message": "No security context is available to allow impersonation.",
    },
    0x000006E6: {
        "code": "RPC_S_INTERNAL_ERROR",
        "message": "An internal error occurred in an RPC.",
    },
    0x000006E7: {
        "code": "RPC_S_ZERO_DIVIDE",
        "message": "The RPC server attempted an integer division by zero.",
    },
    0x000006E8: {
        "code": "RPC_S_ADDRESS_ERROR",
        "message": "An addressing error occurred in the RPC server.",
    },
    0x000006E9: {
        "code": "RPC_S_FP_DIV_ZERO",
        "message": (
            "A floating-point operation at the RPC server caused a division by zero."
        ),
    },
    0x000006EA: {
        "code": "RPC_S_FP_UNDERFLOW",
        "message": "A floating-point underflow occurred at the RPC server.",
    },
    0x000006EB: {
        "code": "RPC_S_FP_OVERFLOW",
        "message": "A floating-point overflow occurred at the RPC server.",
    },
    0x000006EC: {
        "code": "RPC_X_NO_MORE_ENTRIES",
        "message": (
            "The list of RPC servers available for the binding of auto handles has been"
            " exhausted."
        ),
    },
    0x000006ED: {
        "code": "RPC_X_SS_CHAR_TRANS_OPEN_FAIL",
        "message": "Unable to open the character translation table file.",
    },
    0x000006EE: {
        "code": "RPC_X_SS_CHAR_TRANS_SHORT_FILE",
        "message": (
            "The file containing the character translation table has fewer than 512"
            " bytes."
        ),
    },
    0x000006EF: {
        "code": "RPC_X_SS_IN_NULL_CONTEXT",
        "message": (
            "A null context handle was passed from the client to the host during an"
            " RPC."
        ),
    },
    0x000006F1: {
        "code": "RPC_X_SS_CONTEXT_DAMAGED",
        "message": "The context handle changed during an RPC.",
    },
    0x000006F2: {
        "code": "RPC_X_SS_HANDLES_MISMATCH",
        "message": "The binding handles passed to an RPC do not match.",
    },
    0x000006F3: {
        "code": "RPC_X_SS_CANNOT_GET_CALL_HANDLE",
        "message": "The stub is unable to get the RPC handle.",
    },
    0x000006F4: {
        "code": "RPC_X_NULL_REF_POINTER",
        "message": "A null reference pointer was passed to the stub.",
    },
    0x000006F5: {
        "code": "RPC_X_ENUM_VALUE_OUT_OF_RANGE",
        "message": "The enumeration value is out of range.",
    },
    0x000006F6: {
        "code": "RPC_X_BYTE_COUNT_TOO_SMALL",
        "message": "The byte count is too small.",
    },
    0x000006F7: {
        "code": "RPC_X_BAD_STUB_DATA",
        "message": "The stub received bad data.",
    },
    0x000006F8: {
        "code": "ERROR_INVALID_USER_BUFFER",
        "message": "The supplied user buffer is not valid for the requested operation.",
    },
    0x000006F9: {
        "code": "ERROR_UNRECOGNIZED_MEDIA",
        "message": "The disk media is not recognized. It might not be formatted.",
    },
    0x000006FA: {
        "code": "ERROR_NO_TRUST_LSA_SECRET",
        "message": "The workstation does not have a trust secret.",
    },
    0x000006FB: {
        "code": "ERROR_NO_TRUST_SAM_ACCOUNT",
        "message": (
            "The security database on the server does not have a computer account for"
            " this workstation trust relationship."
        ),
    },
    0x000006FC: {
        "code": "ERROR_TRUSTED_DOMAIN_FAILURE",
        "message": (
            "The trust relationship between the primary domain and the trusted domain"
            " failed."
        ),
    },
    0x000006FD: {
        "code": "ERROR_TRUSTED_RELATIONSHIP_FAILURE",
        "message": (
            "The trust relationship between this workstation and the primary domain"
            " failed."
        ),
    },
    0x000006FE: {"code": "ERROR_TRUST_FAILURE", "message": "The network logon failed."},
    0x000006FF: {
        "code": "RPC_S_CALL_IN_PROGRESS",
        "message": "An RPC is already in progress for this thread.",
    },
    0x00000700: {
        "code": "ERROR_NETLOGON_NOT_STARTED",
        "message": (
            "An attempt was made to log on, but the network logon service was not"
            " started."
        ),
    },
    0x00000701: {
        "code": "ERROR_ACCOUNT_EXPIRED",
        "message": "The user's account has expired.",
    },
    0x00000702: {
        "code": "ERROR_REDIRECTOR_HAS_OPEN_HANDLES",
        "message": "The redirector is in use and cannot be unloaded.",
    },
    0x00000703: {
        "code": "ERROR_PRINTER_DRIVER_ALREADY_INSTALLED",
        "message": "The specified printer driver is already installed.",
    },
    0x00000704: {
        "code": "ERROR_UNKNOWN_PORT",
        "message": "The specified port is unknown.",
    },
    0x00000705: {
        "code": "ERROR_UNKNOWN_PRINTER_DRIVER",
        "message": "The printer driver is unknown.",
    },
    0x00000706: {
        "code": "ERROR_UNKNOWN_PRINTPROCESSOR",
        "message": "The print processor is unknown.",
    },
    0x00000707: {
        "code": "ERROR_INVALID_SEPARATOR_FILE",
        "message": "The specified separator file is invalid.",
    },
    0x00000708: {
        "code": "ERROR_INVALID_PRIORITY",
        "message": "The specified priority is invalid.",
    },
    0x00000709: {
        "code": "ERROR_INVALID_PRINTER_NAME",
        "message": "The printer name is invalid.",
    },
    0x0000070A: {
        "code": "ERROR_PRINTER_ALREADY_EXISTS",
        "message": "The printer already exists.",
    },
    0x0000070B: {
        "code": "ERROR_INVALID_PRINTER_COMMAND",
        "message": "The printer command is invalid.",
    },
    0x0000070C: {
        "code": "ERROR_INVALID_DATATYPE",
        "message": "The specified data type is invalid.",
    },
    0x0000070D: {
        "code": "ERROR_INVALID_ENVIRONMENT",
        "message": "The environment specified is invalid.",
    },
    0x0000070E: {
        "code": "RPC_S_NO_MORE_BINDINGS",
        "message": "There are no more bindings.",
    },
    0x0000070F: {
        "code": "ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT",
        "message": (
            "The account used is an interdomain trust account. Use your global user"
            " account or local user account to access this server."
        ),
    },
    0x00000710: {
        "code": "ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT",
        "message": (
            "The account used is a computer account. Use your global user account or"
            " local user account to access this server."
        ),
    },
    0x00000711: {
        "code": "ERROR_NOLOGON_SERVER_TRUST_ACCOUNT",
        "message": (
            "The account used is a server trust account. Use your global user account"
            " or local user account to access this server."
        ),
    },
    0x00000712: {
        "code": "ERROR_DOMAIN_TRUST_INCONSISTENT",
        "message": (
            "The name or SID of the domain specified is inconsistent with the trust"
            " information for that domain."
        ),
    },
    0x00000713: {
        "code": "ERROR_SERVER_HAS_OPEN_HANDLES",
        "message": "The server is in use and cannot be unloaded.",
    },
    0x00000714: {
        "code": "ERROR_RESOURCE_DATA_NOT_FOUND",
        "message": "The specified image file did not contain a resource section.",
    },
    0x00000715: {
        "code": "ERROR_RESOURCE_TYPE_NOT_FOUND",
        "message": "The specified resource type cannot be found in the image file.",
    },
    0x00000716: {
        "code": "ERROR_RESOURCE_NAME_NOT_FOUND",
        "message": "The specified resource name cannot be found in the image file.",
    },
    0x00000717: {
        "code": "ERROR_RESOURCE_LANG_NOT_FOUND",
        "message": (
            "The specified resource language ID cannot be found in the image file."
        ),
    },
    0x00000718: {
        "code": "ERROR_NOT_ENOUGH_QUOTA",
        "message": "Not enough quota is available to process this command.",
    },
    0x00000719: {
        "code": "RPC_S_NO_INTERFACES",
        "message": "No interfaces have been registered.",
    },
    0x0000071A: {"code": "RPC_S_CALL_CANCELLED", "message": "The RPC was canceled."},
    0x0000071B: {
        "code": "RPC_S_BINDING_INCOMPLETE",
        "message": "The binding handle does not contain all the required information.",
    },
    0x0000071C: {
        "code": "RPC_S_COMM_FAILURE",
        "message": "A communications failure occurred during an RPC.",
    },
    0x0000071D: {
        "code": "RPC_S_UNSUPPORTED_AUTHN_LEVEL",
        "message": "The requested authentication level is not supported.",
    },
    0x0000071E: {
        "code": "RPC_S_NO_PRINC_NAME",
        "message": "No principal name is registered.",
    },
    0x0000071F: {
        "code": "RPC_S_NOT_RPC_ERROR",
        "message": "The error specified is not a valid Windows RPC error code.",
    },
    0x00000720: {
        "code": "RPC_S_UUID_LOCAL_ONLY",
        "message": "A UUID that is valid only on this computer has been allocated.",
    },
    0x00000721: {
        "code": "RPC_S_SEC_PKG_ERROR",
        "message": "A security package-specific error occurred.",
    },
    0x00000722: {
        "code": "RPC_S_NOT_CANCELLED",
        "message": "The thread is not canceled.",
    },
    0x00000723: {
        "code": "RPC_X_INVALID_ES_ACTION",
        "message": "Invalid operation on the encoding/decoding handle.",
    },
    0x00000724: {
        "code": "RPC_X_WRONG_ES_VERSION",
        "message": "Incompatible version of the serializing package.",
    },
    0x00000725: {
        "code": "RPC_X_WRONG_STUB_VERSION",
        "message": "Incompatible version of the RPC stub.",
    },
    0x00000726: {
        "code": "RPC_X_INVALID_PIPE_OBJECT",
        "message": "The RPC pipe object is invalid or corrupted.",
    },
    0x00000727: {
        "code": "RPC_X_WRONG_PIPE_ORDER",
        "message": "An invalid operation was attempted on an RPC pipe object.",
    },
    0x00000728: {
        "code": "RPC_X_WRONG_PIPE_VERSION",
        "message": "Unsupported RPC pipe version.",
    },
    0x0000076A: {
        "code": "RPC_S_GROUP_MEMBER_NOT_FOUND",
        "message": "The group member was not found.",
    },
    0x0000076B: {
        "code": "EPT_S_CANT_CREATE",
        "message": "The endpoint mapper database entry could not be created.",
    },
    0x0000076C: {
        "code": "RPC_S_INVALID_OBJECT",
        "message": "The object UUID is the nil UUID.",
    },
    0x0000076D: {
        "code": "ERROR_INVALID_TIME",
        "message": "The specified time is invalid.",
    },
    0x0000076E: {
        "code": "ERROR_INVALID_FORM_NAME",
        "message": "The specified form name is invalid.",
    },
    0x0000076F: {
        "code": "ERROR_INVALID_FORM_SIZE",
        "message": "The specified form size is invalid.",
    },
    0x00000770: {
        "code": "ERROR_ALREADY_WAITING",
        "message": "The specified printer handle is already being waited on.",
    },
    0x00000771: {
        "code": "ERROR_PRINTER_DELETED",
        "message": "The specified printer has been deleted.",
    },
    0x00000772: {
        "code": "ERROR_INVALID_PRINTER_STATE",
        "message": "The state of the printer is invalid.",
    },
    0x00000773: {
        "code": "ERROR_PASSWORD_MUST_CHANGE",
        "message": (
            "The user's password must be changed before logging on the first time."
        ),
    },
    0x00000774: {
        "code": "ERROR_DOMAIN_CONTROLLER_NOT_FOUND",
        "message": "Could not find the domain controller for this domain.",
    },
    0x00000775: {
        "code": "ERROR_ACCOUNT_LOCKED_OUT",
        "message": (
            "The referenced account is currently locked out and cannot be logged on to."
        ),
    },
    0x00000776: {
        "code": "OR_INVALID_OXID",
        "message": "The object exporter specified was not found.",
    },
    0x00000777: {
        "code": "OR_INVALID_OID",
        "message": "The object specified was not found.",
    },
    0x00000778: {
        "code": "OR_INVALID_SET",
        "message": "The object set specified was not found.",
    },
    0x00000779: {
        "code": "RPC_S_SEND_INCOMPLETE",
        "message": "Some data remains to be sent in the request buffer.",
    },
    0x0000077A: {
        "code": "RPC_S_INVALID_ASYNC_HANDLE",
        "message": "Invalid asynchronous RPC handle.",
    },
    0x0000077B: {
        "code": "RPC_S_INVALID_ASYNC_CALL",
        "message": "Invalid asynchronous RPC call handle for this operation.",
    },
    0x0000077C: {
        "code": "RPC_X_PIPE_CLOSED",
        "message": "The RPC pipe object has already been closed.",
    },
    0x0000077D: {
        "code": "RPC_X_PIPE_DISCIPLINE_ERROR",
        "message": "The RPC call completed before all pipes were processed.",
    },
    0x0000077E: {
        "code": "RPC_X_PIPE_EMPTY",
        "message": "No more data is available from the RPC pipe.",
    },
    0x0000077F: {
        "code": "ERROR_NO_SITENAME",
        "message": "No site name is available for this machine.",
    },
    0x00000780: {
        "code": "ERROR_CANT_ACCESS_FILE",
        "message": "The file cannot be accessed by the system.",
    },
    0x00000781: {
        "code": "ERROR_CANT_RESOLVE_FILENAME",
        "message": "The name of the file cannot be resolved by the system.",
    },
    0x00000782: {
        "code": "RPC_S_ENTRY_TYPE_MISMATCH",
        "message": "The entry is not of the expected type.",
    },
    0x00000783: {
        "code": "RPC_S_NOT_ALL_OBJS_EXPORTED",
        "message": "Not all object UUIDs could be exported to the specified entry.",
    },
    0x00000784: {
        "code": "RPC_S_INTERFACE_NOT_EXPORTED",
        "message": "The interface could not be exported to the specified entry.",
    },
    0x00000785: {
        "code": "RPC_S_PROFILE_NOT_ADDED",
        "message": "The specified profile entry could not be added.",
    },
    0x00000786: {
        "code": "RPC_S_PRF_ELT_NOT_ADDED",
        "message": "The specified profile element could not be added.",
    },
    0x00000787: {
        "code": "RPC_S_PRF_ELT_NOT_REMOVED",
        "message": "The specified profile element could not be removed.",
    },
    0x00000788: {
        "code": "RPC_S_GRP_ELT_NOT_ADDED",
        "message": "The group element could not be added.",
    },
    0x00000789: {
        "code": "RPC_S_GRP_ELT_NOT_REMOVED",
        "message": "The group element could not be removed.",
    },
    0x0000078A: {
        "code": "ERROR_KM_DRIVER_BLOCKED",
        "message": (
            "The printer driver is not compatible with a policy enabled on your"
            " computer that blocks Windows NT 4.0 operating system drivers."
        ),
    },
    0x0000078B: {
        "code": "ERROR_CONTEXT_EXPIRED",
        "message": "The context has expired and can no longer be used.",
    },
    0x0000078C: {
        "code": "ERROR_PER_USER_TRUST_QUOTA_EXCEEDED",
        "message": (
            "The current user's delegated trust creation quota has been exceeded."
        ),
    },
    0x0000078D: {
        "code": "ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED",
        "message": "The total delegated trust creation quota has been exceeded.",
    },
    0x0000078E: {
        "code": "ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED",
        "message": (
            "The current user's delegated trust deletion quota has been exceeded."
        ),
    },
    0x0000078F: {
        "code": "ERROR_AUTHENTICATION_FIREWALL_FAILED",
        "message": (
            "Logon failure: The machine you are logging on to is protected by an"
            " authentication firewall. The specified account is not allowed to"
            " authenticate to the machine."
        ),
    },
    0x00000790: {
        "code": "ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED",
        "message": (
            "Remote connections to the Print Spooler are blocked by a policy set on"
            " your machine."
        ),
    },
    0x000007D0: {
        "code": "ERROR_INVALID_PIXEL_FORMAT",
        "message": "The pixel format is invalid.",
    },
    0x000007D1: {
        "code": "ERROR_BAD_DRIVER",
        "message": "The specified driver is invalid.",
    },
    0x000007D2: {
        "code": "ERROR_INVALID_WINDOW_STYLE",
        "message": "The window style or class attribute is invalid for this operation.",
    },
    0x000007D3: {
        "code": "ERROR_METAFILE_NOT_SUPPORTED",
        "message": "The requested metafile operation is not supported.",
    },
    0x000007D4: {
        "code": "ERROR_TRANSFORM_NOT_SUPPORTED",
        "message": "The requested transformation operation is not supported.",
    },
    0x000007D5: {
        "code": "ERROR_CLIPPING_NOT_SUPPORTED",
        "message": "The requested clipping operation is not supported.",
    },
    0x000007DA: {
        "code": "ERROR_INVALID_CMM",
        "message": "The specified color management module is invalid.",
    },
    0x000007DB: {
        "code": "ERROR_INVALID_PROFILE",
        "message": "The specified color profile is invalid.",
    },
    0x000007DC: {
        "code": "ERROR_TAG_NOT_FOUND",
        "message": "The specified tag was not found.",
    },
    0x000007DD: {
        "code": "ERROR_TAG_NOT_PRESENT",
        "message": "A required tag is not present.",
    },
    0x000007DE: {
        "code": "ERROR_DUPLICATE_TAG",
        "message": "The specified tag is already present.",
    },
    0x000007DF: {
        "code": "ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE",
        "message": "The specified color profile is not associated with any device.",
    },
    0x000007E0: {
        "code": "ERROR_PROFILE_NOT_FOUND",
        "message": "The specified color profile was not found.",
    },
    0x000007E1: {
        "code": "ERROR_INVALID_COLORSPACE",
        "message": "The specified color space is invalid.",
    },
    0x000007E2: {
        "code": "ERROR_ICM_NOT_ENABLED",
        "message": "Image Color Management is not enabled.",
    },
    0x000007E3: {
        "code": "ERROR_DELETING_ICM_XFORM",
        "message": "There was an error while deleting the color transform.",
    },
    0x000007E4: {
        "code": "ERROR_INVALID_TRANSFORM",
        "message": "The specified color transform is invalid.",
    },
    0x000007E5: {
        "code": "ERROR_COLORSPACE_MISMATCH",
        "message": "The specified transform does not match the bitmap's color space.",
    },
    0x000007E6: {
        "code": "ERROR_INVALID_COLORINDEX",
        "message": "The specified named color index is not present in the profile.",
    },
    0x000007E7: {
        "code": "ERROR_PROFILE_DOES_NOT_MATCH_DEVICE",
        "message": (
            "The specified profile is intended for a device of a different type than"
            " the specified device."
        ),
    },
    0x00000836: {
        "code": "NERR_NetNotStarted",
        "message": "The workstation driver is not installed.",
    },
    0x00000837: {
        "code": "NERR_UnknownServer",
        "message": "The server could not be located.",
    },
    0x00000838: {
        "code": "NERR_ShareMem",
        "message": (
            "An internal error occurred. The network cannot access a shared memory"
            " segment."
        ),
    },
    0x00000839: {
        "code": "NERR_NoNetworkResource",
        "message": "A network resource shortage occurred.",
    },
    0x0000083A: {
        "code": "NERR_RemoteOnly",
        "message": "This operation is not supported on workstations.",
    },
    0x0000083B: {
        "code": "NERR_DevNotRedirected",
        "message": "The device is not connected.",
    },
    0x0000083C: {
        "code": "ERROR_CONNECTED_OTHER_PASSWORD",
        "message": (
            "The network connection was made successfully, but the user had to be"
            " prompted for a password other than the one originally specified."
        ),
    },
    0x0000083D: {
        "code": "ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT",
        "message": (
            "The network connection was made successfully using default credentials."
        ),
    },
    0x00000842: {
        "code": "NERR_ServerNotStarted",
        "message": "The Server service is not started.",
    },
    0x00000843: {"code": "NERR_ItemNotFound", "message": "The queue is empty."},
    0x00000844: {
        "code": "NERR_UnknownDevDir",
        "message": "The device or directory does not exist.",
    },
    0x00000845: {
        "code": "NERR_RedirectedPath",
        "message": "The operation is invalid on a redirected resource.",
    },
    0x00000846: {
        "code": "NERR_DuplicateShare",
        "message": "The name has already been shared.",
    },
    0x00000847: {
        "code": "NERR_NoRoom",
        "message": "The server is currently out of the requested resource.",
    },
    0x00000849: {
        "code": "NERR_TooManyItems",
        "message": "Requested addition of items exceeds the maximum allowed.",
    },
    0x0000084A: {
        "code": "NERR_InvalidMaxUsers",
        "message": "The Peer service supports only two simultaneous users.",
    },
    0x0000084B: {
        "code": "NERR_BufTooSmall",
        "message": "The API return buffer is too small.",
    },
    0x0000084F: {"code": "NERR_RemoteErr", "message": "A remote API error occurred."},
    0x00000853: {
        "code": "NERR_LanmanIniError",
        "message": "An error occurred when opening or reading the configuration file.",
    },
    0x00000858: {
        "code": "NERR_NetworkError",
        "message": "A general network error occurred.",
    },
    0x00000859: {
        "code": "NERR_WkstaInconsistentState",
        "message": (
            "The Workstation service is in an inconsistent state. Restart the computer"
            " before restarting the Workstation service."
        ),
    },
    0x0000085A: {
        "code": "NERR_WkstaNotStarted",
        "message": "The Workstation service has not been started.",
    },
    0x0000085B: {
        "code": "NERR_BrowserNotStarted",
        "message": "The requested information is not available.",
    },
    0x0000085C: {
        "code": "NERR_InternalError",
        "message": "An internal error occurred.",
    },
    0x0000085D: {
        "code": "NERR_BadTransactConfig",
        "message": "The server is not configured for transactions.",
    },
    0x0000085E: {
        "code": "NERR_InvalidAPI",
        "message": "The requested API is not supported on the remote server.",
    },
    0x0000085F: {"code": "NERR_BadEventName", "message": "The event name is invalid."},
    0x00000860: {
        "code": "NERR_DupNameReboot",
        "message": (
            "The computer name already exists on the network. Change it and reboot the"
            " computer."
        ),
    },
    0x00000862: {
        "code": "NERR_CfgCompNotFound",
        "message": (
            "The specified component could not be found in the configuration"
            " information."
        ),
    },
    0x00000863: {
        "code": "NERR_CfgParamNotFound",
        "message": (
            "The specified parameter could not be found in the configuration"
            " information."
        ),
    },
    0x00000865: {
        "code": "NERR_LineTooLong",
        "message": "A line in the configuration file is too long.",
    },
    0x00000866: {"code": "NERR_QNotFound", "message": "The printer does not exist."},
    0x00000867: {
        "code": "NERR_JobNotFound",
        "message": "The print job does not exist.",
    },
    0x00000868: {
        "code": "NERR_DestNotFound",
        "message": "The printer destination cannot be found.",
    },
    0x00000869: {
        "code": "NERR_DestExists",
        "message": "The printer destination already exists.",
    },
    0x0000086A: {"code": "NERR_QExists", "message": "The print queue already exists."},
    0x0000086B: {"code": "NERR_QNoRoom", "message": "No more printers can be added."},
    0x0000086C: {
        "code": "NERR_JobNoRoom",
        "message": "No more print jobs can be added.",
    },
    0x0000086D: {
        "code": "NERR_DestNoRoom",
        "message": "No more printer destinations can be added.",
    },
    0x0000086E: {
        "code": "NERR_DestIdle",
        "message": (
            "This printer destination is idle and cannot accept control operations."
        ),
    },
    0x0000086F: {
        "code": "NERR_DestInvalidOp",
        "message": (
            "This printer destination request contains an invalid control function."
        ),
    },
    0x00000870: {
        "code": "NERR_ProcNoRespond",
        "message": "The print processor is not responding.",
    },
    0x00000871: {
        "code": "NERR_SpoolerNotLoaded",
        "message": "The spooler is not running.",
    },
    0x00000872: {
        "code": "NERR_DestInvalidState",
        "message": (
            "This operation cannot be performed on the print destination in its current"
            " state."
        ),
    },
    0x00000873: {
        "code": "NERR_QinvalidState",
        "message": (
            "This operation cannot be performed on the print queue in its current"
            " state."
        ),
    },
    0x00000874: {
        "code": "NERR_JobInvalidState",
        "message": (
            "This operation cannot be performed on the print job in its current state."
        ),
    },
    0x00000875: {
        "code": "NERR_SpoolNoMemory",
        "message": "A spooler memory allocation failure occurred.",
    },
    0x00000876: {
        "code": "NERR_DriverNotFound",
        "message": "The device driver does not exist.",
    },
    0x00000877: {
        "code": "NERR_DataTypeInvalid",
        "message": "The data type is not supported by the print processor.",
    },
    0x00000878: {
        "code": "NERR_ProcNotFound",
        "message": "The print processor is not installed.",
    },
    0x00000884: {
        "code": "NERR_ServiceTableLocked",
        "message": "The service database is locked.",
    },
    0x00000885: {
        "code": "NERR_ServiceTableFull",
        "message": "The service table is full.",
    },
    0x00000886: {
        "code": "NERR_ServiceInstalled",
        "message": "The requested service has already been started.",
    },
    0x00000887: {
        "code": "NERR_ServiceEntryLocked",
        "message": "The service does not respond to control actions.",
    },
    0x00000888: {
        "code": "NERR_ServiceNotInstalled",
        "message": "The service has not been started.",
    },
    0x00000889: {
        "code": "NERR_BadServiceName",
        "message": "The service name is invalid.",
    },
    0x0000088A: {
        "code": "NERR_ServiceCtlTimeout",
        "message": "The service is not responding to the control function.",
    },
    0x0000088B: {
        "code": "NERR_ServiceCtlBusy",
        "message": "The service control is busy.",
    },
    0x0000088C: {
        "code": "NERR_BadServiceProgName",
        "message": "The configuration file contains an invalid service program name.",
    },
    0x0000088D: {
        "code": "NERR_ServiceNotCtrl",
        "message": "The service could not be controlled in its present state.",
    },
    0x0000088E: {
        "code": "NERR_ServiceKillProc",
        "message": "The service ended abnormally.",
    },
    0x0000088F: {
        "code": "NERR_ServiceCtlNotValid",
        "message": "The requested pause or stop is not valid for this service.",
    },
    0x00000890: {
        "code": "NERR_NotInDispatchTbl",
        "message": (
            "The service control dispatcher could not find the service name in the"
            " dispatch table."
        ),
    },
    0x00000891: {
        "code": "NERR_BadControlRecv",
        "message": "The service control dispatcher pipe read failed.",
    },
    0x00000892: {
        "code": "NERR_ServiceNotStarting",
        "message": "A thread for the new service could not be created.",
    },
    0x00000898: {
        "code": "NERR_AlreadyLoggedOn",
        "message": "This workstation is already logged on to the LAN.",
    },
    0x00000899: {
        "code": "NERR_NotLoggedOn",
        "message": "The workstation is not logged on to the LAN.",
    },
    0x0000089A: {
        "code": "NERR_BadUsername",
        "message": "The user name or group name parameter is invalid.",
    },
    0x0000089B: {
        "code": "NERR_BadPassword",
        "message": "The password parameter is invalid.",
    },
    0x0000089C: {
        "code": "NERR_UnableToAddName_W",
        "message": "The logon processor did not add the message alias.",
    },
    0x0000089D: {
        "code": "NERR_UnableToAddName_F",
        "message": "The logon processor did not add the message alias.",
    },
    0x0000089E: {
        "code": "NERR_UnableToDelName_W",
        "message": "The logoff processor did not delete the message alias.",
    },
    0x0000089F: {
        "code": "NERR_UnableToDelName_F",
        "message": "The logoff processor did not delete the message alias.",
    },
    0x000008A1: {"code": "NERR_LogonsPaused", "message": "Network logons are paused."},
    0x000008A2: {
        "code": "NERR_LogonServerConflict",
        "message": "A centralized logon server conflict occurred.",
    },
    0x000008A3: {
        "code": "NERR_LogonNoUserPath",
        "message": "The server is configured without a valid user path.",
    },
    0x000008A4: {
        "code": "NERR_LogonScriptError",
        "message": "An error occurred while loading or running the logon script.",
    },
    0x000008A6: {
        "code": "NERR_StandaloneLogon",
        "message": (
            "The logon server was not specified. The computer will be logged on as"
            " STANDALONE."
        ),
    },
    0x000008A7: {
        "code": "NERR_LogonServerNotFound",
        "message": "The logon server could not be found.",
    },
    0x000008A8: {
        "code": "NERR_LogonDomainExists",
        "message": "There is already a logon domain for this computer.",
    },
    0x000008A9: {
        "code": "NERR_NonValidatedLogon",
        "message": "The logon server could not validate the logon.",
    },
    0x000008AB: {
        "code": "NERR_ACFNotFound",
        "message": "The security database could not be found.",
    },
    0x000008AC: {
        "code": "NERR_GroupNotFound",
        "message": "The group name could not be found.",
    },
    0x000008AD: {
        "code": "NERR_UserNotFound",
        "message": "The user name could not be found.",
    },
    0x000008AE: {
        "code": "NERR_ResourceNotFound",
        "message": "The resource name could not be found.",
    },
    0x000008AF: {"code": "NERR_GroupExists", "message": "The group already exists."},
    0x000008B0: {
        "code": "NERR_UserExists",
        "message": "The user account already exists.",
    },
    0x000008B1: {
        "code": "NERR_ResourceExists",
        "message": "The resource permission list already exists.",
    },
    0x000008B2: {
        "code": "NERR_NotPrimary",
        "message": "This operation is allowed only on the PDC of the domain.",
    },
    0x000008B3: {
        "code": "NERR_ACFNotLoaded",
        "message": "The security database has not been started.",
    },
    0x000008B4: {
        "code": "NERR_ACFNoRoom",
        "message": "There are too many names in the user accounts database.",
    },
    0x000008B5: {
        "code": "NERR_ACFFileIOFail",
        "message": "A disk I/O failure occurred.",
    },
    0x000008B6: {
        "code": "NERR_ACFTooManyLists",
        "message": "The limit of 64 entries per resource was exceeded.",
    },
    0x000008B7: {
        "code": "NERR_UserLogon",
        "message": "Deleting a user with a session is not allowed.",
    },
    0x000008B8: {
        "code": "NERR_ACFNoParent",
        "message": "The parent directory could not be located.",
    },
    0x000008B9: {
        "code": "NERR_CanNotGrowSegment",
        "message": "Unable to add to the security database session cache segment.",
    },
    0x000008BA: {
        "code": "NERR_SpeGroupOp",
        "message": "This operation is not allowed on this special group.",
    },
    0x000008BB: {
        "code": "NERR_NotInCache",
        "message": (
            "This user is not cached in the user accounts database session cache."
        ),
    },
    0x000008BC: {
        "code": "NERR_UserInGroup",
        "message": "The user already belongs to this group.",
    },
    0x000008BD: {
        "code": "NERR_UserNotInGroup",
        "message": "The user does not belong to this group.",
    },
    0x000008BE: {
        "code": "NERR_AccountUndefined",
        "message": "This user account is undefined.",
    },
    0x000008BF: {
        "code": "NERR_AccountExpired",
        "message": "This user account has expired.",
    },
    0x000008C0: {
        "code": "NERR_InvalidWorkstation",
        "message": "The user is not allowed to log on from this workstation.",
    },
    0x000008C1: {
        "code": "NERR_InvalidLogonHours",
        "message": "The user is not allowed to log on at this time.",
    },
    0x000008C2: {
        "code": "NERR_PasswordExpired",
        "message": "The password of this user has expired.",
    },
    0x000008C3: {
        "code": "NERR_PasswordCantChange",
        "message": "The password of this user cannot change.",
    },
    0x000008C4: {
        "code": "NERR_PasswordHistConflict",
        "message": "This password cannot be used now.",
    },
    0x000008C5: {
        "code": "NERR_PasswordTooShort",
        "message": (
            "The password does not meet the password policy requirements. Check the"
            " minimum password length, password complexity, and password history"
            " requirements."
        ),
    },
    0x000008C6: {
        "code": "NERR_PasswordTooRecent",
        "message": "The password of this user is too recent to change.",
    },
    0x000008C7: {
        "code": "NERR_InvalidDatabase",
        "message": "The security database is corrupted.",
    },
    0x000008C8: {
        "code": "NERR_DatabaseUpToDate",
        "message": (
            "No updates are necessary to this replicant network or local security"
            " database."
        ),
    },
    0x000008C9: {
        "code": "NERR_SyncRequired",
        "message": "This replicant database is outdated; synchronization is required.",
    },
    0x000008CA: {
        "code": "NERR_UseNotFound",
        "message": "The network connection could not be found.",
    },
    0x000008CB: {"code": "NERR_BadAsgType", "message": "This asg_type is invalid."},
    0x000008CC: {
        "code": "NERR_DeviceIsShared",
        "message": "This device is currently being shared.",
    },
    0x000008DE: {
        "code": "NERR_NoComputerName",
        "message": (
            "The computer name could not be added as a message alias. The name might"
            " already exist on the network."
        ),
    },
    0x000008DF: {
        "code": "NERR_MsgAlreadyStarted",
        "message": "The Messenger service is already started.",
    },
    0x000008E0: {
        "code": "NERR_MsgInitFailed",
        "message": "The Messenger service failed to start.",
    },
    0x000008E1: {
        "code": "NERR_NameNotFound",
        "message": "The message alias could not be found on the network.",
    },
    0x000008E2: {
        "code": "NERR_AlreadyForwarded",
        "message": "This message alias has already been forwarded.",
    },
    0x000008E3: {
        "code": "NERR_AddForwarded",
        "message": "This message alias has been added but is still forwarded.",
    },
    0x000008E4: {
        "code": "NERR_AlreadyExists",
        "message": "This message alias already exists locally.",
    },
    0x000008E5: {
        "code": "NERR_TooManyNames",
        "message": "The maximum number of added message aliases has been exceeded.",
    },
    0x000008E6: {
        "code": "NERR_DelComputerName",
        "message": "The computer name could not be deleted.",
    },
    0x000008E7: {
        "code": "NERR_LocalForward",
        "message": "Messages cannot be forwarded back to the same workstation.",
    },
    0x000008E8: {
        "code": "NERR_GrpMsgProcessor",
        "message": "An error occurred in the domain message processor.",
    },
    0x000008E9: {
        "code": "NERR_PausedRemote",
        "message": (
            "The message was sent, but the recipient has paused the Messenger service."
        ),
    },
    0x000008EA: {
        "code": "NERR_BadReceive",
        "message": "The message was sent but not received.",
    },
    0x000008EB: {
        "code": "NERR_NameInUse",
        "message": "The message alias is currently in use. Try again later.",
    },
    0x000008EC: {
        "code": "NERR_MsgNotStarted",
        "message": "The Messenger service has not been started.",
    },
    0x000008ED: {
        "code": "NERR_NotLocalName",
        "message": "The name is not on the local computer.",
    },
    0x000008EE: {
        "code": "NERR_NoForwardName",
        "message": "The forwarded message alias could not be found on the network.",
    },
    0x000008EF: {
        "code": "NERR_RemoteFull",
        "message": "The message alias table on the remote station is full.",
    },
    0x000008F0: {
        "code": "NERR_NameNotForwarded",
        "message": "Messages for this alias are not currently being forwarded.",
    },
    0x000008F1: {
        "code": "NERR_TruncatedBroadcast",
        "message": "The broadcast message was truncated.",
    },
    0x000008F6: {
        "code": "NERR_InvalidDevice",
        "message": "This is an invalid device name.",
    },
    0x000008F7: {"code": "NERR_WriteFault", "message": "A write fault occurred."},
    0x000008F9: {
        "code": "NERR_DuplicateName",
        "message": "A duplicate message alias exists on the network.",
    },
    0x000008FA: {
        "code": "NERR_DeleteLater",
        "message": "This message alias will be deleted later.",
    },
    0x000008FB: {
        "code": "NERR_IncompleteDel",
        "message": "The message alias was not successfully deleted from all networks.",
    },
    0x000008FC: {
        "code": "NERR_MultipleNets",
        "message": (
            "This operation is not supported on computers with multiple networks."
        ),
    },
    0x00000906: {
        "code": "NERR_NetNameNotFound",
        "message": "This shared resource does not exist.",
    },
    0x00000907: {
        "code": "NERR_DeviceNotShared",
        "message": "This device is not shared.",
    },
    0x00000908: {
        "code": "NERR_ClientNameNotFound",
        "message": "A session does not exist with that computer name.",
    },
    0x0000090A: {
        "code": "NERR_FileIdNotFound",
        "message": "There is not an open file with that identification number.",
    },
    0x0000090B: {
        "code": "NERR_ExecFailure",
        "message": "A failure occurred when executing a remote administration command.",
    },
    0x0000090C: {
        "code": "NERR_TmpFile",
        "message": "A failure occurred when opening a remote temporary file.",
    },
    0x0000090D: {
        "code": "NERR_TooMuchData",
        "message": (
            "The data returned from a remote administration command has been truncated"
            " to 64 KB."
        ),
    },
    0x0000090E: {
        "code": "NERR_DeviceShareConflict",
        "message": (
            "This device cannot be shared as both a spooled and a nonspooled resource."
        ),
    },
    0x0000090F: {
        "code": "NERR_BrowserTableIncomplete",
        "message": "The information in the list of servers might be incorrect.",
    },
    0x00000910: {
        "code": "NERR_NotLocalDomain",
        "message": "The computer is not active in this domain.",
    },
    0x00000911: {
        "code": "NERR_IsDfsShare",
        "message": (
            "The share must be removed from the Distributed File System (DFS) before it"
            " can be deleted."
        ),
    },
    0x0000091B: {
        "code": "NERR_DevInvalidOpCode",
        "message": "The operation is invalid for this device.",
    },
    0x0000091C: {
        "code": "NERR_DevNotFound",
        "message": "This device cannot be shared.",
    },
    0x0000091D: {"code": "NERR_DevNotOpen", "message": "This device was not open."},
    0x0000091E: {
        "code": "NERR_BadQueueDevString",
        "message": "This device name list is invalid.",
    },
    0x0000091F: {
        "code": "NERR_BadQueuePriority",
        "message": "The queue priority is invalid.",
    },
    0x00000921: {
        "code": "NERR_NoCommDevs",
        "message": "There are no shared communication devices.",
    },
    0x00000922: {
        "code": "NERR_QueueNotFound",
        "message": "The queue you specified does not exist.",
    },
    0x00000924: {
        "code": "NERR_BadDevString",
        "message": "This list of devices is invalid.",
    },
    0x00000925: {"code": "NERR_BadDev", "message": "The requested device is invalid."},
    0x00000926: {
        "code": "NERR_InUseBySpooler",
        "message": "This device is already in use by the spooler.",
    },
    0x00000927: {
        "code": "NERR_CommDevInUse",
        "message": "This device is already in use as a communication device.",
    },
    0x0000092F: {
        "code": "NERR_InvalidComputer",
        "message": "This computer name is invalid.",
    },
    0x00000932: {
        "code": "NERR_MaxLenExceeded",
        "message": "The string and prefix specified are too long.",
    },
    0x00000934: {
        "code": "NERR_BadComponent",
        "message": "This path component is invalid.",
    },
    0x00000935: {
        "code": "NERR_CantType",
        "message": "Could not determine the type of input.",
    },
    0x0000093A: {
        "code": "NERR_TooManyEntries",
        "message": "The buffer for types is not big enough.",
    },
    0x00000942: {
        "code": "NERR_ProfileFileTooBig",
        "message": "Profile files cannot exceed 64 KB.",
    },
    0x00000943: {
        "code": "NERR_ProfileOffset",
        "message": "The start offset is out of range.",
    },
    0x00000944: {
        "code": "NERR_ProfileCleanup",
        "message": "The system cannot delete current connections to network resources.",
    },
    0x00000945: {
        "code": "NERR_ProfileUnknownCmd",
        "message": "The system was unable to parse the command line in this file.",
    },
    0x00000946: {
        "code": "NERR_ProfileLoadErr",
        "message": "An error occurred while loading the profile file.",
    },
    0x00000947: {
        "code": "NERR_ProfileSaveErr",
        "message": (
            "Errors occurred while saving the profile file. The profile was partially"
            " saved."
        ),
    },
    0x00000949: {"code": "NERR_LogOverflow", "message": "Log file %1 is full."},
    0x0000094A: {
        "code": "NERR_LogFileChanged",
        "message": "This log file has changed between reads.",
    },
    0x0000094B: {"code": "NERR_LogFileCorrupt", "message": "Log file %1 is corrupt."},
    0x0000094C: {
        "code": "NERR_SourceIsDir",
        "message": "The source path cannot be a directory.",
    },
    0x0000094D: {"code": "NERR_BadSource", "message": "The source path is illegal."},
    0x0000094E: {"code": "NERR_BadDest", "message": "The destination path is illegal."},
    0x0000094F: {
        "code": "NERR_DifferentServers",
        "message": "The source and destination paths are on different servers.",
    },
    0x00000951: {
        "code": "NERR_RunSrvPaused",
        "message": "The Run server you requested is paused.",
    },
    0x00000955: {
        "code": "NERR_ErrCommRunSrv",
        "message": "An error occurred when communicating with a Run server.",
    },
    0x00000957: {
        "code": "NERR_ErrorExecingGhost",
        "message": "An error occurred when starting a background process.",
    },
    0x00000958: {
        "code": "NERR_ShareNotFound",
        "message": "The shared resource you are connected to could not be found.",
    },
    0x00000960: {
        "code": "NERR_InvalidLana",
        "message": "The LAN adapter number is invalid.",
    },
    0x00000961: {
        "code": "NERR_OpenFiles",
        "message": "There are open files on the connection.",
    },
    0x00000962: {
        "code": "NERR_ActiveConns",
        "message": "Active connections still exist.",
    },
    0x00000963: {
        "code": "NERR_BadPasswordCore",
        "message": "This share name or password is invalid.",
    },
    0x00000964: {
        "code": "NERR_DevInUse",
        "message": "The device is being accessed by an active process.",
    },
    0x00000965: {
        "code": "NERR_LocalDrive",
        "message": "The drive letter is in use locally.",
    },
    0x0000097E: {
        "code": "NERR_AlertExists",
        "message": (
            "The specified client is already registered for the specified event."
        ),
    },
    0x0000097F: {"code": "NERR_TooManyAlerts", "message": "The alert table is full."},
    0x00000980: {
        "code": "NERR_NoSuchAlert",
        "message": "An invalid or nonexistent alert name was raised.",
    },
    0x00000981: {
        "code": "NERR_BadRecipient",
        "message": "The alert recipient is invalid.",
    },
    0x00000982: {
        "code": "NERR_AcctLimitExceeded",
        "message": "A user's session with this server has been deleted.",
    },
    0x00000988: {
        "code": "NERR_InvalidLogSeek",
        "message": "The log file does not contain the requested record number.",
    },
    0x00000992: {
        "code": "NERR_BadUasConfig",
        "message": "The user accounts database is not configured correctly.",
    },
    0x00000993: {
        "code": "NERR_InvalidUASOp",
        "message": (
            "This operation is not permitted when the Net Logon service is running."
        ),
    },
    0x00000994: {
        "code": "NERR_LastAdmin",
        "message": "This operation is not allowed on the last administrative account.",
    },
    0x00000995: {
        "code": "NERR_DCNotFound",
        "message": "Could not find the domain controller for this domain.",
    },
    0x00000996: {
        "code": "NERR_LogonTrackingError",
        "message": "Could not set logon information for this user.",
    },
    0x00000997: {
        "code": "NERR_NetlogonNotStarted",
        "message": "The Net Logon service has not been started.",
    },
    0x00000998: {
        "code": "NERR_CanNotGrowUASFile",
        "message": "Unable to add to the user accounts database.",
    },
    0x00000999: {
        "code": "NERR_TimeDiffAtDC",
        "message": "This server's clock is not synchronized with the PDC's clock.",
    },
    0x0000099A: {
        "code": "NERR_PasswordMismatch",
        "message": "A password mismatch has been detected.",
    },
    0x0000099C: {
        "code": "NERR_NoSuchServer",
        "message": "The server identification does not specify a valid server.",
    },
    0x0000099D: {
        "code": "NERR_NoSuchSession",
        "message": "The session identification does not specify a valid session.",
    },
    0x0000099E: {
        "code": "NERR_NoSuchConnection",
        "message": "The connection identification does not specify a valid connection.",
    },
    0x0000099F: {
        "code": "NERR_TooManyServers",
        "message": (
            "There is no space for another entry in the table of available servers."
        ),
    },
    0x000009A0: {
        "code": "NERR_TooManySessions",
        "message": "The server has reached the maximum number of sessions it supports.",
    },
    0x000009A1: {
        "code": "NERR_TooManyConnections",
        "message": (
            "The server has reached the maximum number of connections it supports."
        ),
    },
    0x000009A2: {
        "code": "NERR_TooManyFiles",
        "message": (
            "The server cannot open more files because it has reached its maximum"
            " number."
        ),
    },
    0x000009A3: {
        "code": "NERR_NoAlternateServers",
        "message": "There are no alternate servers registered on this server.",
    },
    0x000009A6: {
        "code": "NERR_TryDownLevel",
        "message": "Try the down-level (remote admin protocol) version of API instead.",
    },
    0x000009B0: {
        "code": "NERR_UPSDriverNotStarted",
        "message": (
            "The uninterruptible power supply (UPS) driver could not be accessed by the"
            " UPS service."
        ),
    },
    0x000009B1: {
        "code": "NERR_UPSInvalidConfig",
        "message": "The UPS service is not configured correctly.",
    },
    0x000009B2: {
        "code": "NERR_UPSInvalidCommPort",
        "message": "The UPS service could not access the specified Comm Port.",
    },
    0x000009B3: {
        "code": "NERR_UPSSignalAsserted",
        "message": (
            "The UPS indicated a line fail or low battery situation. Service not"
            " started."
        ),
    },
    0x000009B4: {
        "code": "NERR_UPSShutdownFailed",
        "message": "The UPS service failed to perform a system shut down.",
    },
    0x000009C4: {
        "code": "NERR_BadDosRetCode",
        "message": "The program below returned an MS-DOS error code.",
    },
    0x000009C5: {
        "code": "NERR_ProgNeedsExtraMem",
        "message": "The program below needs more memory.",
    },
    0x000009C6: {
        "code": "NERR_BadDosFunction",
        "message": "The program below called an unsupported MS-DOS function.",
    },
    0x000009C7: {
        "code": "NERR_RemoteBootFailed",
        "message": "The workstation failed to boot.",
    },
    0x000009C8: {
        "code": "NERR_BadFileCheckSum",
        "message": "The file below is corrupt.",
    },
    0x000009C9: {
        "code": "NERR_NoRplBootSystem",
        "message": "No loader is specified in the boot-block definition file.",
    },
    0x000009CA: {
        "code": "NERR_RplLoadrNetBiosErr",
        "message": (
            "NetBIOS returned an error: The network control blocks (NCBs) and Server"
            " Message Block (SMB) are dumped above."
        ),
    },
    0x000009CB: {
        "code": "NERR_RplLoadrDiskErr",
        "message": "A disk I/O error occurred.",
    },
    0x000009CC: {
        "code": "NERR_ImageParamErr",
        "message": "Image parameter substitution failed.",
    },
    0x000009CD: {
        "code": "NERR_TooManyImageParams",
        "message": "Too many image parameters cross disk sector boundaries.",
    },
    0x000009CE: {
        "code": "NERR_NonDosFloppyUsed",
        "message": "The image was not generated from an MS-DOS disk formatted with /S.",
    },
    0x000009CF: {
        "code": "NERR_RplBootRestart",
        "message": "Remote boot will be restarted later.",
    },
    0x000009D0: {
        "code": "NERR_RplSrvrCallFailed",
        "message": "The call to the Remoteboot server failed.",
    },
    0x000009D1: {
        "code": "NERR_CantConnectRplSrvr",
        "message": "Cannot connect to the Remoteboot server.",
    },
    0x000009D2: {
        "code": "NERR_CantOpenImageFile",
        "message": "Cannot open image file on the Remoteboot server.",
    },
    0x000009D3: {
        "code": "NERR_CallingRplSrvr",
        "message": "Connecting to the Remoteboot server.",
    },
    0x000009D4: {
        "code": "NERR_StartingRplBoot",
        "message": "Connecting to the Remoteboot server.",
    },
    0x000009D5: {
        "code": "NERR_RplBootServiceTerm",
        "message": (
            "Remote boot service was stopped, check the error log for the cause of the"
            " problem."
        ),
    },
    0x000009D6: {
        "code": "NERR_RplBootStartFailed",
        "message": (
            "Remote boot startup failed; check the error log for the cause of the"
            " problem."
        ),
    },
    0x000009D7: {
        "code": "NERR_RPL_CONNECTED",
        "message": "A second connection to a Remoteboot resource is not allowed.",
    },
    0x000009F6: {
        "code": "NERR_BrowserConfiguredToNotRun",
        "message": "The browser service was configured with MaintainServerList=No.",
    },
    0x00000A32: {
        "code": "NERR_RplNoAdaptersStarted",
        "message": (
            "Service failed to start because none of the network adapters started with"
            " this service."
        ),
    },
    0x00000A33: {
        "code": "NERR_RplBadRegistry",
        "message": (
            "Service failed to start due to bad startup information in the registry."
        ),
    },
    0x00000A34: {
        "code": "NERR_RplBadDatabase",
        "message": "Service failed to start because its database is absent or corrupt.",
    },
    0x00000A35: {
        "code": "NERR_RplRplfilesShare",
        "message": "Service failed to start because the RPLFILES share is absent.",
    },
    0x00000A36: {
        "code": "NERR_RplNotRplServer",
        "message": "Service failed to start because the RPLUSER group is absent.",
    },
    0x00000A37: {
        "code": "NERR_RplCannotEnum",
        "message": "Cannot enumerate service records.",
    },
    0x00000A38: {
        "code": "NERR_RplWkstaInfoCorrupted",
        "message": "Workstation record information has been corrupted.",
    },
    0x00000A39: {
        "code": "NERR_RplWkstaNotFound",
        "message": "Workstation record was not found.",
    },
    0x00000A3A: {
        "code": "NERR_RplWkstaNameUnavailable",
        "message": "Workstation name is in use by some other workstation.",
    },
    0x00000A3B: {
        "code": "NERR_RplProfileInfoCorrupted",
        "message": "Profile record information has been corrupted.",
    },
    0x00000A3C: {
        "code": "NERR_RplProfileNotFound",
        "message": "Profile record was not found.",
    },
    0x00000A3D: {
        "code": "NERR_RplProfileNameUnavailable",
        "message": "Profile name is in use by some other profile.",
    },
    0x00000A3E: {
        "code": "NERR_RplProfileNotEmpty",
        "message": "There are workstations using this profile.",
    },
    0x00000A3F: {
        "code": "NERR_RplConfigInfoCorrupted",
        "message": "Configuration record information has been corrupted.",
    },
    0x00000A40: {
        "code": "NERR_RplConfigNotFound",
        "message": "Configuration record was not found.",
    },
    0x00000A41: {
        "code": "NERR_RplAdapterInfoCorrupted",
        "message": "Adapter ID record information has been corrupted.",
    },
    0x00000A42: {
        "code": "NERR_RplInternal",
        "message": "An internal service error has occurred.",
    },
    0x00000A43: {
        "code": "NERR_RplVendorInfoCorrupted",
        "message": "Vendor ID record information has been corrupted.",
    },
    0x00000A44: {
        "code": "NERR_RplBootInfoCorrupted",
        "message": "Boot block record information has been corrupted.",
    },
    0x00000A45: {
        "code": "NERR_RplWkstaNeedsUserAcct",
        "message": "The user account for this workstation record is missing.",
    },
    0x00000A46: {
        "code": "NERR_RplNeedsRPLUSERAcct",
        "message": "The RPLUSER local group could not be found.",
    },
    0x00000A47: {
        "code": "NERR_RplBootNotFound",
        "message": "Boot block record was not found.",
    },
    0x00000A48: {
        "code": "NERR_RplIncompatibleProfile",
        "message": "Chosen profile is incompatible with this workstation.",
    },
    0x00000A49: {
        "code": "NERR_RplAdapterNameUnavailable",
        "message": "Chosen network adapter ID is in use by some other workstation.",
    },
    0x00000A4A: {
        "code": "NERR_RplConfigNotEmpty",
        "message": "There are profiles using this configuration.",
    },
    0x00000A4B: {
        "code": "NERR_RplBootInUse",
        "message": (
            "There are workstations, profiles, or configurations using this boot block."
        ),
    },
    0x00000A4C: {
        "code": "NERR_RplBackupDatabase",
        "message": "Service failed to back up the Remoteboot database.",
    },
    0x00000A4D: {
        "code": "NERR_RplAdapterNotFound",
        "message": "Adapter record was not found.",
    },
    0x00000A4E: {
        "code": "NERR_RplVendorNotFound",
        "message": "Vendor record was not found.",
    },
    0x00000A4F: {
        "code": "NERR_RplVendorNameUnavailable",
        "message": "Vendor name is in use by some other vendor record.",
    },
    0x00000A50: {
        "code": "NERR_RplBootNameUnavailable",
        "message": (
            "The boot name or vendor ID is in use by some other boot block record."
        ),
    },
    0x00000A51: {
        "code": "NERR_RplConfigNameUnavailable",
        "message": "The configuration name is in use by some other configuration.",
    },
    0x00000A64: {
        "code": "NERR_DfsInternalCorruption",
        "message": "The internal database maintained by the DFS service is corrupt.",
    },
    0x00000A65: {
        "code": "NERR_DfsVolumeDataCorrupt",
        "message": "One of the records in the internal DFS database is corrupt.",
    },
    0x00000A66: {
        "code": "NERR_DfsNoSuchVolume",
        "message": (
            "There is no DFS name whose entry path matches the input entry path."
        ),
    },
    0x00000A67: {
        "code": "NERR_DfsVolumeAlreadyExists",
        "message": "A root or link with the given name already exists.",
    },
    0x00000A68: {
        "code": "NERR_DfsAlreadyShared",
        "message": "The server share specified is already shared in the DFS.",
    },
    0x00000A69: {
        "code": "NERR_DfsNoSuchShare",
        "message": (
            "The indicated server share does not support the indicated DFS namespace."
        ),
    },
    0x00000A6A: {
        "code": "NERR_DfsNotALeafVolume",
        "message": "The operation is not valid in this portion of the namespace.",
    },
    0x00000A6B: {
        "code": "NERR_DfsLeafVolume",
        "message": "The operation is not valid in this portion of the namespace.",
    },
    0x00000A6C: {
        "code": "NERR_DfsVolumeHasMultipleServers",
        "message": "The operation is ambiguous because the link has multiple servers.",
    },
    0x00000A6D: {
        "code": "NERR_DfsCantCreateJunctionPoint",
        "message": "Unable to create a link.",
    },
    0x00000A6E: {
        "code": "NERR_DfsServerNotDfsAware",
        "message": "The server is not DFS-aware.",
    },
    0x00000A6F: {
        "code": "NERR_DfsBadRenamePath",
        "message": "The specified rename target path is invalid.",
    },
    0x00000A70: {
        "code": "NERR_DfsVolumeIsOffline",
        "message": "The specified DFS link is offline.",
    },
    0x00000A71: {
        "code": "NERR_DfsNoSuchServer",
        "message": "The specified server is not a server for this link.",
    },
    0x00000A72: {
        "code": "NERR_DfsCyclicalName",
        "message": "A cycle in the DFS name was detected.",
    },
    0x00000A73: {
        "code": "NERR_DfsNotSupportedInServerDfs",
        "message": "The operation is not supported on a server-based DFS.",
    },
    0x00000A74: {
        "code": "NERR_DfsDuplicateService",
        "message": "This link is already supported by the specified server share.",
    },
    0x00000A75: {
        "code": "NERR_DfsCantRemoveLastServerShare",
        "message": "Cannot remove the last server share supporting this root or link.",
    },
    0x00000A76: {
        "code": "NERR_DfsVolumeIsInterDfs",
        "message": "The operation is not supported for an inter-DFS link.",
    },
    0x00000A77: {
        "code": "NERR_DfsInconsistent",
        "message": "The internal state of the DFS Service has become inconsistent.",
    },
    0x00000A78: {
        "code": "NERR_DfsServerUpgraded",
        "message": "The DFS Service has been installed on the specified server.",
    },
    0x00000A79: {
        "code": "NERR_DfsDataIsIdentical",
        "message": "The DFS data being reconciled is identical.",
    },
    0x00000A7A: {
        "code": "NERR_DfsCantRemoveDfsRoot",
        "message": "The DFS root cannot be deleted. Uninstall DFS if required.",
    },
    0x00000A7B: {
        "code": "NERR_DfsChildOrParentInDfs",
        "message": "A child or parent directory of the share is already in a DFS.",
    },
    0x00000A82: {"code": "NERR_DfsInternalError", "message": "DFS internal error."},
    0x00000A83: {
        "code": "NERR_SetupAlreadyJoined",
        "message": "This machine is already joined to a domain.",
    },
    0x00000A84: {
        "code": "NERR_SetupNotJoined",
        "message": "This machine is not currently joined to a domain.",
    },
    0x00000A85: {
        "code": "NERR_SetupDomainController",
        "message": (
            "This machine is a domain controller and cannot be unjoined from a domain."
        ),
    },
    0x00000A86: {
        "code": "NERR_DefaultJoinRequired",
        "message": (
            "The destination domain controller does not support creating machine"
            " accounts in organizational units (OUs)."
        ),
    },
    0x00000A87: {
        "code": "NERR_InvalidWorkgroupName",
        "message": "The specified workgroup name is invalid.",
    },
    0x00000A88: {
        "code": "NERR_NameUsesIncompatibleCodePage",
        "message": (
            "The specified computer name is incompatible with the default language used"
            " on the domain controller."
        ),
    },
    0x00000A89: {
        "code": "NERR_ComputerAccountNotFound",
        "message": "The specified computer account could not be found.",
    },
    0x00000A8A: {
        "code": "NERR_PersonalSku",
        "message": "This version of Windows cannot be joined to a domain.",
    },
    0x00000A8D: {
        "code": "NERR_PasswordMustChange",
        "message": "The password must change at the next logon.",
    },
    0x00000A8E: {
        "code": "NERR_AccountLockedOut",
        "message": "The account is locked out.",
    },
    0x00000A8F: {
        "code": "NERR_PasswordTooLong",
        "message": "The password is too long.",
    },
    0x00000A90: {
        "code": "NERR_PasswordNotComplexEnough",
        "message": "The password does not meet the complexity policy.",
    },
    0x00000A91: {
        "code": "NERR_PasswordFilterError",
        "message": (
            "The password does not meet the requirements of the password filter DLLs."
        ),
    },
    0x00000BB8: {
        "code": "ERROR_UNKNOWN_PRINT_MONITOR",
        "message": "The specified print monitor is unknown.",
    },
    0x00000BB9: {
        "code": "ERROR_PRINTER_DRIVER_IN_USE",
        "message": "The specified printer driver is currently in use.",
    },
    0x00000BBA: {
        "code": "ERROR_SPOOL_FILE_NOT_FOUND",
        "message": "The spool file was not found.",
    },
    0x00000BBB: {
        "code": "ERROR_SPL_NO_STARTDOC",
        "message": "A StartDocPrinter call was not issued.",
    },
    0x00000BBC: {
        "code": "ERROR_SPL_NO_ADDJOB",
        "message": "An AddJob call was not issued.",
    },
    0x00000BBD: {
        "code": "ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED",
        "message": "The specified print processor has already been installed.",
    },
    0x00000BBE: {
        "code": "ERROR_PRINT_MONITOR_ALREADY_INSTALLED",
        "message": "The specified print monitor has already been installed.",
    },
    0x00000BBF: {
        "code": "ERROR_INVALID_PRINT_MONITOR",
        "message": "The specified print monitor does not have the required functions.",
    },
    0x00000BC0: {
        "code": "ERROR_PRINT_MONITOR_IN_USE",
        "message": "The specified print monitor is currently in use.",
    },
    0x00000BC1: {
        "code": "ERROR_PRINTER_HAS_JOBS_QUEUED",
        "message": (
            "The requested operation is not allowed when there are jobs queued to the"
            " printer."
        ),
    },
    0x00000BC2: {
        "code": "ERROR_SUCCESS_REBOOT_REQUIRED",
        "message": (
            "The requested operation is successful. Changes will not be effective until"
            " the system is rebooted."
        ),
    },
    0x00000BC3: {
        "code": "ERROR_SUCCESS_RESTART_REQUIRED",
        "message": (
            "The requested operation is successful. Changes will not be effective until"
            " the service is restarted."
        ),
    },
    0x00000BC4: {
        "code": "ERROR_PRINTER_NOT_FOUND",
        "message": "No printers were found.",
    },
    0x00000BC5: {
        "code": "ERROR_PRINTER_DRIVER_WARNED",
        "message": "The printer driver is known to be unreliable.",
    },
    0x00000BC6: {
        "code": "ERROR_PRINTER_DRIVER_BLOCKED",
        "message": "The printer driver is known to harm the system.",
    },
    0x00000BC7: {
        "code": "ERROR_PRINTER_DRIVER_PACKAGE_IN_USE",
        "message": "The specified printer driver package is currently in use.",
    },
    0x00000BC8: {
        "code": "ERROR_CORE_DRIVER_PACKAGE_NOT_FOUND",
        "message": (
            "Unable to find a core driver package that is required by the printer"
            " driver package."
        ),
    },
    0x00000BC9: {
        "code": "ERROR_FAIL_REBOOT_REQUIRED",
        "message": (
            "The requested operation failed. A system reboot is required to roll back"
            " changes made."
        ),
    },
    0x00000BCA: {
        "code": "ERROR_FAIL_REBOOT_INITIATED",
        "message": (
            "The requested operation failed. A system reboot has been initiated to roll"
            " back changes made."
        ),
    },
    0x00000BCB: {
        "code": "ERROR_PRINTER_DRIVER_DOWNLOAD_NEEDED",
        "message": (
            "The specified printer driver was not found on the system and needs to be"
            " downloaded."
        ),
    },
    0x00000BCE: {
        "code": "ERROR_PRINTER_NOT_SHAREABLE",
        "message": "The specified printer cannot be shared.",
    },
    0x00000F6E: {
        "code": "ERROR_IO_REISSUE_AS_CACHED",
        "message": "Reissue the given operation as a cached I/O operation.",
    },
    0x00000FA0: {
        "code": "ERROR_WINS_INTERNAL",
        "message": (
            "Windows Internet Name Service (WINS) encountered an error while processing"
            " the command."
        ),
    },
    0x00000FA1: {
        "code": "ERROR_CAN_NOT_DEL_LOCAL_WINS",
        "message": "The local WINS cannot be deleted.",
    },
    0x00000FA2: {
        "code": "ERROR_STATIC_INIT",
        "message": "The importation from the file failed.",
    },
    0x00000FA3: {
        "code": "ERROR_INC_BACKUP",
        "message": "The backup failed. Was a full backup done before?",
    },
    0x00000FA4: {
        "code": "ERROR_FULL_BACKUP",
        "message": (
            "The backup failed. Check the directory to which you are backing the"
            " database."
        ),
    },
    0x00000FA5: {
        "code": "ERROR_REC_NON_EXISTENT",
        "message": "The name does not exist in the WINS database.",
    },
    0x00000FA6: {
        "code": "ERROR_RPL_NOT_ALLOWED",
        "message": "Replication with a nonconfigured partner is not allowed.",
    },
    0x00000FD2: {
        "code": "PEERDIST_ERROR_CONTENTINFO_VERSION_UNSUPPORTED",
        "message": "The version of the supplied content information is not supported.",
    },
    0x00000FD3: {
        "code": "PEERDIST_ERROR_CANNOT_PARSE_CONTENTINFO",
        "message": "The supplied content information is malformed.",
    },
    0x00000FD4: {
        "code": "PEERDIST_ERROR_MISSING_DATA",
        "message": "The requested data cannot be found in local or peer caches.",
    },
    0x00000FD5: {
        "code": "PEERDIST_ERROR_NO_MORE",
        "message": "No more data is available or required.",
    },
    0x00000FD6: {
        "code": "PEERDIST_ERROR_NOT_INITIALIZED",
        "message": "The supplied object has not been initialized.",
    },
    0x00000FD7: {
        "code": "PEERDIST_ERROR_ALREADY_INITIALIZED",
        "message": "The supplied object has already been initialized.",
    },
    0x00000FD8: {
        "code": "PEERDIST_ERROR_SHUTDOWN_IN_PROGRESS",
        "message": "A shutdown operation is already in progress.",
    },
    0x00000FD9: {
        "code": "PEERDIST_ERROR_INVALIDATED",
        "message": "The supplied object has already been invalidated.",
    },
    0x00000FDA: {
        "code": "PEERDIST_ERROR_ALREADY_EXISTS",
        "message": "An element already exists and was not replaced.",
    },
    0x00000FDB: {
        "code": "PEERDIST_ERROR_OPERATION_NOTFOUND",
        "message": (
            "Cannot cancel the requested operation as it has already been completed."
        ),
    },
    0x00000FDC: {
        "code": "PEERDIST_ERROR_ALREADY_COMPLETED",
        "message": (
            "Cannot perform the requested operation because it has already been carried"
            " out."
        ),
    },
    0x00000FDD: {
        "code": "PEERDIST_ERROR_OUT_OF_BOUNDS",
        "message": "An operation accessed data beyond the bounds of valid data.",
    },
    0x00000FDE: {
        "code": "PEERDIST_ERROR_VERSION_UNSUPPORTED",
        "message": "The requested version is not supported.",
    },
    0x00000FDF: {
        "code": "PEERDIST_ERROR_INVALID_CONFIGURATION",
        "message": "A configuration value is invalid.",
    },
    0x00000FE0: {
        "code": "PEERDIST_ERROR_NOT_LICENSED",
        "message": "The SKU is not licensed.",
    },
    0x00000FE1: {
        "code": "PEERDIST_ERROR_SERVICE_UNAVAILABLE",
        "message": (
            "PeerDist Service is still initializing and will be available shortly."
        ),
    },
    0x00001004: {
        "code": "ERROR_DHCP_ADDRESS_CONFLICT",
        "message": (
            "The Dynamic Host Configuration Protocol (DHCP) client has obtained an IP"
            " address that is already in use on the network. The local interface will"
            " be disabled until the DHCP client can obtain a new address."
        ),
    },
    0x00001068: {
        "code": "ERROR_WMI_GUID_NOT_FOUND",
        "message": (
            "The GUID passed was not recognized as valid by a WMI data provider."
        ),
    },
    0x00001069: {
        "code": "ERROR_WMI_INSTANCE_NOT_FOUND",
        "message": (
            "The instance name passed was not recognized as valid by a WMI data"
            " provider."
        ),
    },
    0x0000106A: {
        "code": "ERROR_WMI_ITEMID_NOT_FOUND",
        "message": (
            "The data item ID passed was not recognized as valid by a WMI data"
            " provider."
        ),
    },
    0x0000106B: {
        "code": "ERROR_WMI_TRY_AGAIN",
        "message": "The WMI request could not be completed and should be retried.",
    },
    0x0000106C: {
        "code": "ERROR_WMI_DP_NOT_FOUND",
        "message": "The WMI data provider could not be located.",
    },
    0x0000106D: {
        "code": "ERROR_WMI_UNRESOLVED_INSTANCE_REF",
        "message": (
            "The WMI data provider references an instance set that has not been"
            " registered."
        ),
    },
    0x0000106E: {
        "code": "ERROR_WMI_ALREADY_ENABLED",
        "message": "The WMI data block or event notification has already been enabled.",
    },
    0x0000106F: {
        "code": "ERROR_WMI_GUID_DISCONNECTED",
        "message": "The WMI data block is no longer available.",
    },
    0x00001070: {
        "code": "ERROR_WMI_SERVER_UNAVAILABLE",
        "message": "The WMI data service is not available.",
    },
    0x00001071: {
        "code": "ERROR_WMI_DP_FAILED",
        "message": "The WMI data provider failed to carry out the request.",
    },
    0x00001072: {
        "code": "ERROR_WMI_INVALID_MOF",
        "message": "The WMI Managed Object Format (MOF) information is not valid.",
    },
    0x00001073: {
        "code": "ERROR_WMI_INVALID_REGINFO",
        "message": "The WMI registration information is not valid.",
    },
    0x00001074: {
        "code": "ERROR_WMI_ALREADY_DISABLED",
        "message": (
            "The WMI data block or event notification has already been disabled."
        ),
    },
    0x00001075: {
        "code": "ERROR_WMI_READ_ONLY",
        "message": "The WMI data item or data block is read-only.",
    },
    0x00001076: {
        "code": "ERROR_WMI_SET_FAILURE",
        "message": "The WMI data item or data block could not be changed.",
    },
    0x000010CC: {
        "code": "ERROR_INVALID_MEDIA",
        "message": "The media identifier does not represent a valid medium.",
    },
    0x000010CD: {
        "code": "ERROR_INVALID_LIBRARY",
        "message": "The library identifier does not represent a valid library.",
    },
    0x000010CE: {
        "code": "ERROR_INVALID_MEDIA_POOL",
        "message": "The media pool identifier does not represent a valid media pool.",
    },
    0x000010CF: {
        "code": "ERROR_DRIVE_MEDIA_MISMATCH",
        "message": (
            "The drive and medium are not compatible, or they exist in different"
            " libraries."
        ),
    },
    0x000010D0: {
        "code": "ERROR_MEDIA_OFFLINE",
        "message": (
            "The medium currently exists in an offline library and must be online to"
            " perform this operation."
        ),
    },
    0x000010D1: {
        "code": "ERROR_LIBRARY_OFFLINE",
        "message": "The operation cannot be performed on an offline library.",
    },
    0x000010D2: {
        "code": "ERROR_EMPTY",
        "message": "The library, drive, or media pool is empty.",
    },
    0x000010D3: {
        "code": "ERROR_NOT_EMPTY",
        "message": (
            "The library, drive, or media pool must be empty to perform this operation."
        ),
    },
    0x000010D4: {
        "code": "ERROR_MEDIA_UNAVAILABLE",
        "message": "No media is currently available in this media pool or library.",
    },
    0x000010D5: {
        "code": "ERROR_RESOURCE_DISABLED",
        "message": "A resource required for this operation is disabled.",
    },
    0x000010D6: {
        "code": "ERROR_INVALID_CLEANER",
        "message": "The media identifier does not represent a valid cleaner.",
    },
    0x000010D7: {
        "code": "ERROR_UNABLE_TO_CLEAN",
        "message": "The drive cannot be cleaned or does not support cleaning.",
    },
    0x000010D8: {
        "code": "ERROR_OBJECT_NOT_FOUND",
        "message": "The object identifier does not represent a valid object.",
    },
    0x000010D9: {
        "code": "ERROR_DATABASE_FAILURE",
        "message": "Unable to read from or write to the database.",
    },
    0x000010DA: {"code": "ERROR_DATABASE_FULL", "message": "The database is full."},
    0x000010DB: {
        "code": "ERROR_MEDIA_INCOMPATIBLE",
        "message": "The medium is not compatible with the device or media pool.",
    },
    0x000010DC: {
        "code": "ERROR_RESOURCE_NOT_PRESENT",
        "message": "The resource required for this operation does not exist.",
    },
    0x000010DD: {
        "code": "ERROR_INVALID_OPERATION",
        "message": "The operation identifier is not valid.",
    },
    0x000010DE: {
        "code": "ERROR_MEDIA_NOT_AVAILABLE",
        "message": "The media is not mounted or ready for use.",
    },
    0x000010DF: {
        "code": "ERROR_DEVICE_NOT_AVAILABLE",
        "message": "The device is not ready for use.",
    },
    0x000010E0: {
        "code": "ERROR_REQUEST_REFUSED",
        "message": "The operator or administrator has refused the request.",
    },
    0x000010E1: {
        "code": "ERROR_INVALID_DRIVE_OBJECT",
        "message": "The drive identifier does not represent a valid drive.",
    },
    0x000010E2: {
        "code": "ERROR_LIBRARY_FULL",
        "message": "Library is full. No slot is available for use.",
    },
    0x000010E3: {
        "code": "ERROR_MEDIUM_NOT_ACCESSIBLE",
        "message": "The transport cannot access the medium.",
    },
    0x000010E4: {
        "code": "ERROR_UNABLE_TO_LOAD_MEDIUM",
        "message": "Unable to load the medium into the drive.",
    },
    0x000010E5: {
        "code": "ERROR_UNABLE_TO_INVENTORY_DRIVE",
        "message": "Unable to retrieve the drive status.",
    },
    0x000010E6: {
        "code": "ERROR_UNABLE_TO_INVENTORY_SLOT",
        "message": "Unable to retrieve the slot status.",
    },
    0x000010E7: {
        "code": "ERROR_UNABLE_TO_INVENTORY_TRANSPORT",
        "message": "Unable to retrieve status about the transport.",
    },
    0x000010E8: {
        "code": "ERROR_TRANSPORT_FULL",
        "message": "Cannot use the transport because it is already in use.",
    },
    0x000010E9: {
        "code": "ERROR_CONTROLLING_IEPORT",
        "message": "Unable to open or close the inject/eject port.",
    },
    0x000010EA: {
        "code": "ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA",
        "message": "Unable to eject the medium because it is in a drive.",
    },
    0x000010EB: {
        "code": "ERROR_CLEANER_SLOT_SET",
        "message": "A cleaner slot is already reserved.",
    },
    0x000010EC: {
        "code": "ERROR_CLEANER_SLOT_NOT_SET",
        "message": "A cleaner slot is not reserved.",
    },
    0x000010ED: {
        "code": "ERROR_CLEANER_CARTRIDGE_SPENT",
        "message": (
            "The cleaner cartridge has performed the maximum number of drive cleanings."
        ),
    },
    0x000010EE: {
        "code": "ERROR_UNEXPECTED_OMID",
        "message": "Unexpected on-medium identifier.",
    },
    0x000010EF: {
        "code": "ERROR_CANT_DELETE_LAST_ITEM",
        "message": (
            "The last remaining item in this group or resource cannot be deleted."
        ),
    },
    0x000010F0: {
        "code": "ERROR_MESSAGE_EXCEEDS_MAX_SIZE",
        "message": (
            "The message provided exceeds the maximum size allowed for this parameter."
        ),
    },
    0x000010F1: {
        "code": "ERROR_VOLUME_CONTAINS_SYS_FILES",
        "message": "The volume contains system or paging files.",
    },
    0x000010F2: {
        "code": "ERROR_INDIGENOUS_TYPE",
        "message": (
            "The media type cannot be removed from this library because at least one"
            " drive in the library reports it can support this media type."
        ),
    },
    0x000010F3: {
        "code": "ERROR_NO_SUPPORTING_DRIVES",
        "message": (
            "This offline media cannot be mounted on this system because no enabled"
            " drives are present that can be used."
        ),
    },
    0x000010F4: {
        "code": "ERROR_CLEANER_CARTRIDGE_INSTALLED",
        "message": "A cleaner cartridge is present in the tape library.",
    },
    0x000010F5: {
        "code": "ERROR_IEPORT_FULL",
        "message": "Cannot use the IEport because it is not empty.",
    },
    0x000010FE: {
        "code": "ERROR_FILE_OFFLINE",
        "message": "The remote storage service was not able to recall the file.",
    },
    0x000010FF: {
        "code": "ERROR_REMOTE_STORAGE_NOT_ACTIVE",
        "message": "The remote storage service is not operational at this time.",
    },
    0x00001100: {
        "code": "ERROR_REMOTE_STORAGE_MEDIA_ERROR",
        "message": "The remote storage service encountered a media error.",
    },
    0x00001126: {
        "code": "ERROR_NOT_A_REPARSE_POINT",
        "message": "The file or directory is not a reparse point.",
    },
    0x00001127: {
        "code": "ERROR_REPARSE_ATTRIBUTE_CONFLICT",
        "message": (
            "The reparse point attribute cannot be set because it conflicts with an"
            " existing attribute."
        ),
    },
    0x00001128: {
        "code": "ERROR_INVALID_REPARSE_DATA",
        "message": "The data present in the reparse point buffer is invalid.",
    },
    0x00001129: {
        "code": "ERROR_REPARSE_TAG_INVALID",
        "message": "The tag present in the reparse point buffer is invalid.",
    },
    0x0000112A: {
        "code": "ERROR_REPARSE_TAG_MISMATCH",
        "message": (
            "There is a mismatch between the tag specified in the request and the tag"
            " present in the reparse point."
        ),
    },
    0x00001194: {
        "code": "ERROR_VOLUME_NOT_SIS_ENABLED",
        "message": "Single Instance Storage (SIS) is not available on this volume.",
    },
    0x00001389: {
        "code": "ERROR_DEPENDENT_RESOURCE_EXISTS",
        "message": (
            "The operation cannot be completed because other resources depend on this"
            " resource."
        ),
    },
    0x0000138A: {
        "code": "ERROR_DEPENDENCY_NOT_FOUND",
        "message": "The cluster resource dependency cannot be found.",
    },
    0x0000138B: {
        "code": "ERROR_DEPENDENCY_ALREADY_EXISTS",
        "message": (
            "The cluster resource cannot be made dependent on the specified resource"
            " because it is already dependent."
        ),
    },
    0x0000138C: {
        "code": "ERROR_RESOURCE_NOT_ONLINE",
        "message": "The cluster resource is not online.",
    },
    0x0000138D: {
        "code": "ERROR_HOST_NODE_NOT_AVAILABLE",
        "message": "A cluster node is not available for this operation.",
    },
    0x0000138E: {
        "code": "ERROR_RESOURCE_NOT_AVAILABLE",
        "message": "The cluster resource is not available.",
    },
    0x0000138F: {
        "code": "ERROR_RESOURCE_NOT_FOUND",
        "message": "The cluster resource could not be found.",
    },
    0x00001390: {
        "code": "ERROR_SHUTDOWN_CLUSTER",
        "message": "The cluster is being shut down.",
    },
    0x00001391: {
        "code": "ERROR_CANT_EVICT_ACTIVE_NODE",
        "message": (
            "A cluster node cannot be evicted from the cluster unless the node is down"
            " or it is the last node."
        ),
    },
    0x00001392: {
        "code": "ERROR_OBJECT_ALREADY_EXISTS",
        "message": "The object already exists.",
    },
    0x00001393: {
        "code": "ERROR_OBJECT_IN_LIST",
        "message": "The object is already in the list.",
    },
    0x00001394: {
        "code": "ERROR_GROUP_NOT_AVAILABLE",
        "message": "The cluster group is not available for any new requests.",
    },
    0x00001395: {
        "code": "ERROR_GROUP_NOT_FOUND",
        "message": "The cluster group could not be found.",
    },
    0x00001396: {
        "code": "ERROR_GROUP_NOT_ONLINE",
        "message": (
            "The operation could not be completed because the cluster group is not"
            " online."
        ),
    },
    0x00001397: {
        "code": "ERROR_HOST_NODE_NOT_RESOURCE_OWNER",
        "message": (
            "The operation failed because either the specified cluster node is not the"
            " owner of the resource, or the node is not a possible owner of the"
            " resource."
        ),
    },
    0x00001398: {
        "code": "ERROR_HOST_NODE_NOT_GROUP_OWNER",
        "message": (
            "The operation failed because either the specified cluster node is not the"
            " owner of the group, or the node is not a possible owner of the group."
        ),
    },
    0x00001399: {
        "code": "ERROR_RESMON_CREATE_FAILED",
        "message": (
            "The cluster resource could not be created in the specified resource"
            " monitor."
        ),
    },
    0x0000139A: {
        "code": "ERROR_RESMON_ONLINE_FAILED",
        "message": (
            "The cluster resource could not be brought online by the resource monitor."
        ),
    },
    0x0000139B: {
        "code": "ERROR_RESOURCE_ONLINE",
        "message": (
            "The operation could not be completed because the cluster resource is"
            " online."
        ),
    },
    0x0000139C: {
        "code": "ERROR_QUORUM_RESOURCE",
        "message": (
            "The cluster resource could not be deleted or brought offline because it is"
            " the quorum resource."
        ),
    },
    0x0000139D: {
        "code": "ERROR_NOT_QUORUM_CAPABLE",
        "message": (
            "The cluster could not make the specified resource a quorum resource"
            " because it is not capable of being a quorum resource."
        ),
    },
    0x0000139E: {
        "code": "ERROR_CLUSTER_SHUTTING_DOWN",
        "message": "The cluster software is shutting down.",
    },
    0x0000139F: {
        "code": "ERROR_INVALID_STATE",
        "message": (
            "The group or resource is not in the correct state to perform the requested"
            " operation."
        ),
    },
    0x000013A0: {
        "code": "ERROR_RESOURCE_PROPERTIES_STORED",
        "message": (
            "The properties were stored but not all changes will take effect until the"
            " next time the resource is brought online."
        ),
    },
    0x000013A1: {
        "code": "ERROR_NOT_QUORUM_CLASS",
        "message": (
            "The cluster could not make the specified resource a quorum resource"
            " because it does not belong to a shared storage class."
        ),
    },
    0x000013A2: {
        "code": "ERROR_CORE_RESOURCE",
        "message": (
            "The cluster resource could not be deleted because it is a core resource."
        ),
    },
    0x000013A3: {
        "code": "ERROR_QUORUM_RESOURCE_ONLINE_FAILED",
        "message": "The quorum resource failed to come online.",
    },
    0x000013A4: {
        "code": "ERROR_QUORUMLOG_OPEN_FAILED",
        "message": "The quorum log could not be created or mounted successfully.",
    },
    0x000013A5: {
        "code": "ERROR_CLUSTERLOG_CORRUPT",
        "message": "The cluster log is corrupt.",
    },
    0x000013A6: {
        "code": "ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE",
        "message": (
            "The record could not be written to the cluster log because it exceeds the"
            " maximum size."
        ),
    },
    0x000013A7: {
        "code": "ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE",
        "message": "The cluster log exceeds its maximum size.",
    },
    0x000013A8: {
        "code": "ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND",
        "message": "No checkpoint record was found in the cluster log.",
    },
    0x000013A9: {
        "code": "ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE",
        "message": (
            "The minimum required disk space needed for logging is not available."
        ),
    },
    0x000013AA: {
        "code": "ERROR_QUORUM_OWNER_ALIVE",
        "message": (
            "The cluster node failed to take control of the quorum resource because the"
            " resource is owned by another active node."
        ),
    },
    0x000013AB: {
        "code": "ERROR_NETWORK_NOT_AVAILABLE",
        "message": "A cluster network is not available for this operation.",
    },
    0x000013AC: {
        "code": "ERROR_NODE_NOT_AVAILABLE",
        "message": "A cluster node is not available for this operation.",
    },
    0x000013AD: {
        "code": "ERROR_ALL_NODES_NOT_AVAILABLE",
        "message": "All cluster nodes must be running to perform this operation.",
    },
    0x000013AE: {
        "code": "ERROR_RESOURCE_FAILED",
        "message": "A cluster resource failed.",
    },
    0x000013AF: {
        "code": "ERROR_CLUSTER_INVALID_NODE",
        "message": "The cluster node is not valid.",
    },
    0x000013B0: {
        "code": "ERROR_CLUSTER_NODE_EXISTS",
        "message": "The cluster node already exists.",
    },
    0x000013B1: {
        "code": "ERROR_CLUSTER_JOIN_IN_PROGRESS",
        "message": "A node is in the process of joining the cluster.",
    },
    0x000013B2: {
        "code": "ERROR_CLUSTER_NODE_NOT_FOUND",
        "message": "The cluster node was not found.",
    },
    0x000013B3: {
        "code": "ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND",
        "message": "The cluster local node information was not found.",
    },
    0x000013B4: {
        "code": "ERROR_CLUSTER_NETWORK_EXISTS",
        "message": "The cluster network already exists.",
    },
    0x000013B5: {
        "code": "ERROR_CLUSTER_NETWORK_NOT_FOUND",
        "message": "The cluster network was not found.",
    },
    0x000013B6: {
        "code": "ERROR_CLUSTER_NETINTERFACE_EXISTS",
        "message": "The cluster network interface already exists.",
    },
    0x000013B7: {
        "code": "ERROR_CLUSTER_NETINTERFACE_NOT_FOUND",
        "message": "The cluster network interface was not found.",
    },
    0x000013B8: {
        "code": "ERROR_CLUSTER_INVALID_REQUEST",
        "message": "The cluster request is not valid for this object.",
    },
    0x000013B9: {
        "code": "ERROR_CLUSTER_INVALID_NETWORK_PROVIDER",
        "message": "The cluster network provider is not valid.",
    },
    0x000013BA: {
        "code": "ERROR_CLUSTER_NODE_DOWN",
        "message": "The cluster node is down.",
    },
    0x000013BB: {
        "code": "ERROR_CLUSTER_NODE_UNREACHABLE",
        "message": "The cluster node is not reachable.",
    },
    0x000013BC: {
        "code": "ERROR_CLUSTER_NODE_NOT_MEMBER",
        "message": "The cluster node is not a member of the cluster.",
    },
    0x000013BD: {
        "code": "ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS",
        "message": "A cluster join operation is not in progress.",
    },
    0x000013BE: {
        "code": "ERROR_CLUSTER_INVALID_NETWORK",
        "message": "The cluster network is not valid.",
    },
    0x000013C0: {"code": "ERROR_CLUSTER_NODE_UP", "message": "The cluster node is up."},
    0x000013C1: {
        "code": "ERROR_CLUSTER_IPADDR_IN_USE",
        "message": "The cluster IP address is already in use.",
    },
    0x000013C2: {
        "code": "ERROR_CLUSTER_NODE_NOT_PAUSED",
        "message": "The cluster node is not paused.",
    },
    0x000013C3: {
        "code": "ERROR_CLUSTER_NO_SECURITY_CONTEXT",
        "message": "No cluster security context is available.",
    },
    0x000013C4: {
        "code": "ERROR_CLUSTER_NETWORK_NOT_INTERNAL",
        "message": (
            "The cluster network is not configured for internal cluster communication."
        ),
    },
    0x000013C5: {
        "code": "ERROR_CLUSTER_NODE_ALREADY_UP",
        "message": "The cluster node is already up.",
    },
    0x000013C6: {
        "code": "ERROR_CLUSTER_NODE_ALREADY_DOWN",
        "message": "The cluster node is already down.",
    },
    0x000013C7: {
        "code": "ERROR_CLUSTER_NETWORK_ALREADY_ONLINE",
        "message": "The cluster network is already online.",
    },
    0x000013C8: {
        "code": "ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE",
        "message": "The cluster network is already offline.",
    },
    0x000013C9: {
        "code": "ERROR_CLUSTER_NODE_ALREADY_MEMBER",
        "message": "The cluster node is already a member of the cluster.",
    },
    0x000013CA: {
        "code": "ERROR_CLUSTER_LAST_INTERNAL_NETWORK",
        "message": (
            "The cluster network is the only one configured for internal cluster"
            " communication between two or more active cluster nodes. The internal"
            " communication capability cannot be removed from the network."
        ),
    },
    0x000013CB: {
        "code": "ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS",
        "message": (
            "One or more cluster resources depend on the network to provide service to"
            " clients. The client access capability cannot be removed from the network."
        ),
    },
    0x000013CC: {
        "code": "ERROR_INVALID_OPERATION_ON_QUORUM",
        "message": (
            "This operation cannot be performed on the cluster resource because it is"
            " the quorum resource. This quorum resource cannot be brought offline and"
            " its possible owners list cannot be modified."
        ),
    },
    0x000013CD: {
        "code": "ERROR_DEPENDENCY_NOT_ALLOWED",
        "message": (
            "The cluster quorum resource is not allowed to have any dependencies."
        ),
    },
    0x000013CE: {
        "code": "ERROR_CLUSTER_NODE_PAUSED",
        "message": "The cluster node is paused.",
    },
    0x000013CF: {
        "code": "ERROR_NODE_CANT_HOST_RESOURCE",
        "message": (
            "The cluster resource cannot be brought online. The owner node cannot run"
            " this resource."
        ),
    },
    0x000013D0: {
        "code": "ERROR_CLUSTER_NODE_NOT_READY",
        "message": "The cluster node is not ready to perform the requested operation.",
    },
    0x000013D1: {
        "code": "ERROR_CLUSTER_NODE_SHUTTING_DOWN",
        "message": "The cluster node is shutting down.",
    },
    0x000013D2: {
        "code": "ERROR_CLUSTER_JOIN_ABORTED",
        "message": "The cluster join operation was aborted.",
    },
    0x000013D3: {
        "code": "ERROR_CLUSTER_INCOMPATIBLE_VERSIONS",
        "message": (
            "The cluster join operation failed due to incompatible software versions"
            " between the joining node and its sponsor."
        ),
    },
    0x000013D4: {
        "code": "ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED",
        "message": (
            "This resource cannot be created because the cluster has reached the limit"
            " on the number of resources it can monitor."
        ),
    },
    0x000013D5: {
        "code": "ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED",
        "message": (
            "The system configuration changed during the cluster join or form"
            " operation. The join or form operation was aborted."
        ),
    },
    0x000013D6: {
        "code": "ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND",
        "message": "The specified resource type was not found.",
    },
    0x000013D7: {
        "code": "ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED",
        "message": (
            "The specified node does not support a resource of this type. This might be"
            " due to version inconsistencies or due to the absence of the resource DLL"
            " on this node."
        ),
    },
    0x000013D8: {
        "code": "ERROR_CLUSTER_RESNAME_NOT_FOUND",
        "message": (
            "The specified resource name is not supported by this resource DLL. This"
            " might be due to a bad (or changed) name supplied to the resource DLL."
        ),
    },
    0x000013D9: {
        "code": "ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED",
        "message": "No authentication package could be registered with the RPC server.",
    },
    0x000013DA: {
        "code": "ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST",
        "message": (
            "You cannot bring the group online because the owner of the group is not in"
            " the preferred list for the group. To change the owner node for the group,"
            " move the group."
        ),
    },
    0x000013DB: {
        "code": "ERROR_CLUSTER_DATABASE_SEQMISMATCH",
        "message": (
            "The join operation failed because the cluster database sequence number has"
            " changed or is incompatible with the locker node. This can happen during a"
            " join operation if the cluster database was changing during the join."
        ),
    },
    0x000013DC: {
        "code": "ERROR_RESMON_INVALID_STATE",
        "message": (
            "The resource monitor will not allow the fail operation to be performed"
            " while the resource is in its current state. This can happen if the"
            " resource is in a pending state."
        ),
    },
    0x000013DD: {
        "code": "ERROR_CLUSTER_GUM_NOT_LOCKER",
        "message": (
            "A non-locker code received a request to reserve the lock for making global"
            " updates."
        ),
    },
    0x000013DE: {
        "code": "ERROR_QUORUM_DISK_NOT_FOUND",
        "message": "The quorum disk could not be located by the cluster service.",
    },
    0x000013DF: {
        "code": "ERROR_DATABASE_BACKUP_CORRUPT",
        "message": "The backed-up cluster database is possibly corrupt.",
    },
    0x000013E0: {
        "code": "ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT",
        "message": "A DFS root already exists in this cluster node.",
    },
    0x000013E1: {
        "code": "ERROR_RESOURCE_PROPERTY_UNCHANGEABLE",
        "message": (
            "An attempt to modify a resource property failed because it conflicts with"
            " another existing property."
        ),
    },
    0x00001702: {
        "code": "ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE",
        "message": (
            "An operation was attempted that is incompatible with the current"
            " membership state of the node."
        ),
    },
    0x00001703: {
        "code": "ERROR_CLUSTER_QUORUMLOG_NOT_FOUND",
        "message": "The quorum resource does not contain the quorum log.",
    },
    0x00001704: {
        "code": "ERROR_CLUSTER_MEMBERSHIP_HALT",
        "message": (
            "The membership engine requested shutdown of the cluster service on this"
            " node."
        ),
    },
    0x00001705: {
        "code": "ERROR_CLUSTER_INSTANCE_ID_MISMATCH",
        "message": (
            "The join operation failed because the cluster instance ID of the joining"
            " node does not match the cluster instance ID of the sponsor node."
        ),
    },
    0x00001706: {
        "code": "ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP",
        "message": (
            "A matching cluster network for the specified IP address could not be"
            " found."
        ),
    },
    0x00001707: {
        "code": "ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH",
        "message": (
            "The actual data type of the property did not match the expected data type"
            " of the property."
        ),
    },
    0x00001708: {
        "code": "ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP",
        "message": (
            "The cluster node was evicted from the cluster successfully, but the node"
            " was not cleaned up. To determine what clean-up steps failed and how to"
            " recover, see the Failover Clustering application event log using Event"
            " Viewer."
        ),
    },
    0x00001709: {
        "code": "ERROR_CLUSTER_PARAMETER_MISMATCH",
        "message": (
            "Two or more parameter values specified for a resource's properties are in"
            " conflict."
        ),
    },
    0x0000170A: {
        "code": "ERROR_NODE_CANNOT_BE_CLUSTERED",
        "message": "This computer cannot be made a member of a cluster.",
    },
    0x0000170B: {
        "code": "ERROR_CLUSTER_WRONG_OS_VERSION",
        "message": (
            "This computer cannot be made a member of a cluster because it does not"
            " have the correct version of Windows installed."
        ),
    },
    0x0000170C: {
        "code": "ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME",
        "message": (
            "A cluster cannot be created with the specified cluster name because that"
            " cluster name is already in use. Specify a different name for the cluster."
        ),
    },
    0x0000170D: {
        "code": "ERROR_CLUSCFG_ALREADY_COMMITTED",
        "message": "The cluster configuration action has already been committed.",
    },
    0x0000170E: {
        "code": "ERROR_CLUSCFG_ROLLBACK_FAILED",
        "message": "The cluster configuration action could not be rolled back.",
    },
    0x0000170F: {
        "code": "ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT",
        "message": (
            "The drive letter assigned to a system disk on one node conflicted with the"
            " drive letter assigned to a disk on another node."
        ),
    },
    0x00001710: {
        "code": "ERROR_CLUSTER_OLD_VERSION",
        "message": (
            "One or more nodes in the cluster are running a version of Windows that"
            " does not support this operation."
        ),
    },
    0x00001711: {
        "code": "ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME",
        "message": (
            "The name of the corresponding computer account does not match the network"
            " name for this resource."
        ),
    },
    0x00001712: {
        "code": "ERROR_CLUSTER_NO_NET_ADAPTERS",
        "message": "No network adapters are available.",
    },
    0x00001713: {
        "code": "ERROR_CLUSTER_POISONED",
        "message": "The cluster node has been poisoned.",
    },
    0x00001714: {
        "code": "ERROR_CLUSTER_GROUP_MOVING",
        "message": (
            "The group is unable to accept the request because it is moving to another"
            " node."
        ),
    },
    0x00001715: {
        "code": "ERROR_CLUSTER_RESOURCE_TYPE_BUSY",
        "message": (
            "The resource type cannot accept the request because it is too busy"
            " performing another operation."
        ),
    },
    0x00001716: {
        "code": "ERROR_RESOURCE_CALL_TIMED_OUT",
        "message": "The call to the cluster resource DLL timed out.",
    },
    0x00001717: {
        "code": "ERROR_INVALID_CLUSTER_IPV6_ADDRESS",
        "message": (
            "The address is not valid for an IPv6 Address resource. A global IPv6"
            " address is required, and it must match a cluster network. Compatibility"
            " addresses are not permitted."
        ),
    },
    0x00001718: {
        "code": "ERROR_CLUSTER_INTERNAL_INVALID_FUNCTION",
        "message": (
            "An internal cluster error occurred. A call to an invalid function was"
            " attempted."
        ),
    },
    0x00001719: {
        "code": "ERROR_CLUSTER_PARAMETER_OUT_OF_BOUNDS",
        "message": "A parameter value is out of acceptable range.",
    },
    0x0000171A: {
        "code": "ERROR_CLUSTER_PARTIAL_SEND",
        "message": (
            "A network error occurred while sending data to another node in the"
            " cluster. The number of bytes transmitted was less than required."
        ),
    },
    0x0000171B: {
        "code": "ERROR_CLUSTER_REGISTRY_INVALID_FUNCTION",
        "message": "An invalid cluster registry operation was attempted.",
    },
    0x0000171C: {
        "code": "ERROR_CLUSTER_INVALID_STRING_TERMINATION",
        "message": "An input string of characters is not properly terminated.",
    },
    0x0000171D: {
        "code": "ERROR_CLUSTER_INVALID_STRING_FORMAT",
        "message": (
            "An input string of characters is not in a valid format for the data it"
            " represents."
        ),
    },
    0x0000171E: {
        "code": "ERROR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS",
        "message": (
            "An internal cluster error occurred. A cluster database transaction was"
            " attempted while a transaction was already in progress."
        ),
    },
    0x0000171F: {
        "code": "ERROR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS",
        "message": (
            "An internal cluster error occurred. There was an attempt to commit a"
            " cluster database transaction while no transaction was in progress."
        ),
    },
    0x00001720: {
        "code": "ERROR_CLUSTER_NULL_DATA",
        "message": (
            "An internal cluster error occurred. Data was not properly initialized."
        ),
    },
    0x00001721: {
        "code": "ERROR_CLUSTER_PARTIAL_READ",
        "message": (
            "An error occurred while reading from a stream of data. An unexpected"
            " number of bytes was returned."
        ),
    },
    0x00001722: {
        "code": "ERROR_CLUSTER_PARTIAL_WRITE",
        "message": (
            "An error occurred while writing to a stream of data. The required number"
            " of bytes could not be written."
        ),
    },
    0x00001723: {
        "code": "ERROR_CLUSTER_CANT_DESERIALIZE_DATA",
        "message": "An error occurred while deserializing a stream of cluster data.",
    },
    0x00001724: {
        "code": "ERROR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT",
        "message": (
            "One or more property values for this resource are in conflict with one or"
            " more property values associated with its dependent resources."
        ),
    },
    0x00001725: {
        "code": "ERROR_CLUSTER_NO_QUORUM",
        "message": "A quorum of cluster nodes was not present to form a cluster.",
    },
    0x00001726: {
        "code": "ERROR_CLUSTER_INVALID_IPV6_NETWORK",
        "message": (
            "The cluster network is not valid for an IPv6 address resource, or it does"
            " not match the configured address."
        ),
    },
    0x00001727: {
        "code": "ERROR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK",
        "message": (
            "The cluster network is not valid for an IPv6 tunnel resource. Check the"
            " configuration of the IP Address resource on which the IPv6 tunnel"
            " resource depends."
        ),
    },
    0x00001728: {
        "code": "ERROR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP",
        "message": "Quorum resource cannot reside in the available storage group.",
    },
    0x00001770: {
        "code": "ERROR_ENCRYPTION_FAILED",
        "message": "The specified file could not be encrypted.",
    },
    0x00001771: {
        "code": "ERROR_DECRYPTION_FAILED",
        "message": "The specified file could not be decrypted.",
    },
    0x00001772: {
        "code": "ERROR_FILE_ENCRYPTED",
        "message": (
            "The specified file is encrypted and the user does not have the ability to"
            " decrypt it."
        ),
    },
    0x00001773: {
        "code": "ERROR_NO_RECOVERY_POLICY",
        "message": (
            "There is no valid encryption recovery policy configured for this system."
        ),
    },
    0x00001774: {
        "code": "ERROR_NO_EFS",
        "message": "The required encryption driver is not loaded for this system.",
    },
    0x00001775: {
        "code": "ERROR_WRONG_EFS",
        "message": (
            "The file was encrypted with a different encryption driver than is"
            " currently loaded."
        ),
    },
    0x00001776: {
        "code": "ERROR_NO_USER_KEYS",
        "message": (
            "There are no Encrypting File System (EFS) keys defined for the user."
        ),
    },
    0x00001777: {
        "code": "ERROR_FILE_NOT_ENCRYPTED",
        "message": "The specified file is not encrypted.",
    },
    0x00001778: {
        "code": "ERROR_NOT_EXPORT_FORMAT",
        "message": "The specified file is not in the defined EFS export format.",
    },
    0x00001779: {
        "code": "ERROR_FILE_READ_ONLY",
        "message": "The specified file is read-only.",
    },
    0x0000177A: {
        "code": "ERROR_DIR_EFS_DISALLOWED",
        "message": "The directory has been disabled for encryption.",
    },
    0x0000177B: {
        "code": "ERROR_EFS_SERVER_NOT_TRUSTED",
        "message": "The server is not trusted for remote encryption operation.",
    },
    0x0000177C: {
        "code": "ERROR_BAD_RECOVERY_POLICY",
        "message": (
            "Recovery policy configured for this system contains invalid recovery"
            " certificate."
        ),
    },
    0x0000177D: {
        "code": "ERROR_EFS_ALG_BLOB_TOO_BIG",
        "message": (
            "The encryption algorithm used on the source file needs a bigger key buffer"
            " than the one on the destination file."
        ),
    },
    0x0000177E: {
        "code": "ERROR_VOLUME_NOT_SUPPORT_EFS",
        "message": "The disk partition does not support file encryption.",
    },
    0x0000177F: {
        "code": "ERROR_EFS_DISABLED",
        "message": "This machine is disabled for file encryption.",
    },
    0x00001780: {
        "code": "ERROR_EFS_VERSION_NOT_SUPPORT",
        "message": "A newer system is required to decrypt this encrypted file.",
    },
    0x00001781: {
        "code": "ERROR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE",
        "message": (
            "The remote server sent an invalid response for a file being opened with"
            " client-side encryption."
        ),
    },
    0x00001782: {
        "code": "ERROR_CS_ENCRYPTION_UNSUPPORTED_SERVER",
        "message": (
            "Client-side encryption is not supported by the remote server even though"
            " it claims to support it."
        ),
    },
    0x00001783: {
        "code": "ERROR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE",
        "message": (
            "File is encrypted and should be opened in client-side encryption mode."
        ),
    },
    0x00001784: {
        "code": "ERROR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE",
        "message": (
            "A new encrypted file is being created and a $EFS needs to be provided."
        ),
    },
    0x00001785: {
        "code": "ERROR_CS_ENCRYPTION_FILE_NOT_CSE",
        "message": (
            "The SMB client requested a client-side extension (CSE) file system control"
            " (FSCTL) on a non-CSE file."
        ),
    },
    0x000017E6: {
        "code": "ERROR_NO_BROWSER_SERVERS_FOUND",
        "message": "The list of servers for this workgroup is not currently available",
    },
    0x00001838: {
        "code": "SCHED_E_SERVICE_NOT_LOCALSYSTEM",
        "message": (
            "The Task Scheduler service must be configured to run in the System account"
            " to function properly. Individual tasks can be configured to run in other"
            " accounts."
        ),
    },
    0x000019C8: {
        "code": "ERROR_LOG_SECTOR_INVALID",
        "message": "The log service encountered an invalid log sector.",
    },
    0x000019C9: {
        "code": "ERROR_LOG_SECTOR_PARITY_INVALID",
        "message": (
            "The log service encountered a log sector with invalid block parity."
        ),
    },
    0x000019CA: {
        "code": "ERROR_LOG_SECTOR_REMAPPED",
        "message": "The log service encountered a remapped log sector.",
    },
    0x000019CB: {
        "code": "ERROR_LOG_BLOCK_INCOMPLETE",
        "message": "The log service encountered a partial or incomplete log block.",
    },
    0x000019CC: {
        "code": "ERROR_LOG_INVALID_RANGE",
        "message": (
            "The log service encountered an attempt to access data outside the active"
            " log range."
        ),
    },
    0x000019CD: {
        "code": "ERROR_LOG_BLOCKS_EXHAUSTED",
        "message": "The log service user marshaling buffers are exhausted.",
    },
    0x000019CE: {
        "code": "ERROR_LOG_READ_CONTEXT_INVALID",
        "message": (
            "The log service encountered an attempt to read from a marshaling area with"
            " an invalid read context."
        ),
    },
    0x000019CF: {
        "code": "ERROR_LOG_RESTART_INVALID",
        "message": "The log service encountered an invalid log restart area.",
    },
    0x000019D0: {
        "code": "ERROR_LOG_BLOCK_VERSION",
        "message": "The log service encountered an invalid log block version.",
    },
    0x000019D1: {
        "code": "ERROR_LOG_BLOCK_INVALID",
        "message": "The log service encountered an invalid log block.",
    },
    0x000019D2: {
        "code": "ERROR_LOG_READ_MODE_INVALID",
        "message": (
            "The log service encountered an attempt to read the log with an invalid"
            " read mode."
        ),
    },
    0x000019D3: {
        "code": "ERROR_LOG_NO_RESTART",
        "message": "The log service encountered a log stream with no restart area.",
    },
    0x000019D4: {
        "code": "ERROR_LOG_METADATA_CORRUPT",
        "message": "The log service encountered a corrupted metadata file.",
    },
    0x000019D5: {
        "code": "ERROR_LOG_METADATA_INVALID",
        "message": (
            "The log service encountered a metadata file that could not be created by"
            " the log file system."
        ),
    },
    0x000019D6: {
        "code": "ERROR_LOG_METADATA_INCONSISTENT",
        "message": (
            "The log service encountered a metadata file with inconsistent data."
        ),
    },
    0x000019D7: {
        "code": "ERROR_LOG_RESERVATION_INVALID",
        "message": (
            "The log service encountered an attempt to erroneous allocate or dispose"
            " reservation space."
        ),
    },
    0x000019D8: {
        "code": "ERROR_LOG_CANT_DELETE",
        "message": "The log service cannot delete a log file or file system container.",
    },
    0x000019D9: {
        "code": "ERROR_LOG_CONTAINER_LIMIT_EXCEEDED",
        "message": (
            "The log service has reached the maximum allowable containers allocated to"
            " a log file."
        ),
    },
    0x000019DA: {
        "code": "ERROR_LOG_START_OF_LOG",
        "message": (
            "The log service has attempted to read or write backward past the start of"
            " the log."
        ),
    },
    0x000019DB: {
        "code": "ERROR_LOG_POLICY_ALREADY_INSTALLED",
        "message": (
            "The log policy could not be installed because a policy of the same type is"
            " already present."
        ),
    },
    0x000019DC: {
        "code": "ERROR_LOG_POLICY_NOT_INSTALLED",
        "message": (
            "The log policy in question was not installed at the time of the request."
        ),
    },
    0x000019DD: {
        "code": "ERROR_LOG_POLICY_INVALID",
        "message": "The installed set of policies on the log is invalid.",
    },
    0x000019DE: {
        "code": "ERROR_LOG_POLICY_CONFLICT",
        "message": (
            "A policy on the log in question prevented the operation from completing."
        ),
    },
    0x000019DF: {
        "code": "ERROR_LOG_PINNED_ARCHIVE_TAIL",
        "message": (
            "Log space cannot be reclaimed because the log is pinned by the archive"
            " tail."
        ),
    },
    0x000019E0: {
        "code": "ERROR_LOG_RECORD_NONEXISTENT",
        "message": "The log record is not a record in the log file.",
    },
    0x000019E1: {
        "code": "ERROR_LOG_RECORDS_RESERVED_INVALID",
        "message": (
            "The number of reserved log records or the adjustment of the number of"
            " reserved log records is invalid."
        ),
    },
    0x000019E2: {
        "code": "ERROR_LOG_SPACE_RESERVED_INVALID",
        "message": (
            "The reserved log space or the adjustment of the log space is invalid."
        ),
    },
    0x000019E3: {
        "code": "ERROR_LOG_TAIL_INVALID",
        "message": (
            "A new or existing archive tail or base of the active log is invalid."
        ),
    },
    0x000019E4: {"code": "ERROR_LOG_FULL", "message": "The log space is exhausted."},
    0x000019E5: {
        "code": "ERROR_COULD_NOT_RESIZE_LOG",
        "message": "The log could not be set to the requested size.",
    },
    0x000019E6: {
        "code": "ERROR_LOG_MULTIPLEXED",
        "message": (
            "The log is multiplexed; no direct writes to the physical log are allowed."
        ),
    },
    0x000019E7: {
        "code": "ERROR_LOG_DEDICATED",
        "message": "The operation failed because the log is a dedicated log.",
    },
    0x000019E8: {
        "code": "ERROR_LOG_ARCHIVE_NOT_IN_PROGRESS",
        "message": "The operation requires an archive context.",
    },
    0x000019E9: {
        "code": "ERROR_LOG_ARCHIVE_IN_PROGRESS",
        "message": "Log archival is in progress.",
    },
    0x000019EA: {
        "code": "ERROR_LOG_EPHEMERAL",
        "message": (
            "The operation requires a non-ephemeral log, but the log is ephemeral."
        ),
    },
    0x000019EB: {
        "code": "ERROR_LOG_NOT_ENOUGH_CONTAINERS",
        "message": (
            "The log must have at least two containers before it can be read from or"
            " written to."
        ),
    },
    0x000019EC: {
        "code": "ERROR_LOG_CLIENT_ALREADY_REGISTERED",
        "message": "A log client has already registered on the stream.",
    },
    0x000019ED: {
        "code": "ERROR_LOG_CLIENT_NOT_REGISTERED",
        "message": "A log client has not been registered on the stream.",
    },
    0x000019EE: {
        "code": "ERROR_LOG_FULL_HANDLER_IN_PROGRESS",
        "message": "A request has already been made to handle the log full condition.",
    },
    0x000019EF: {
        "code": "ERROR_LOG_CONTAINER_READ_FAILED",
        "message": (
            "The log service encountered an error when attempting to read from a log"
            " container."
        ),
    },
    0x000019F0: {
        "code": "ERROR_LOG_CONTAINER_WRITE_FAILED",
        "message": (
            "The log service encountered an error when attempting to write to a log"
            " container."
        ),
    },
    0x000019F1: {
        "code": "ERROR_LOG_CONTAINER_OPEN_FAILED",
        "message": (
            "The log service encountered an error when attempting to open a log"
            " container."
        ),
    },
    0x000019F2: {
        "code": "ERROR_LOG_CONTAINER_STATE_INVALID",
        "message": (
            "The log service encountered an invalid container state when attempting a"
            " requested action."
        ),
    },
    0x000019F3: {
        "code": "ERROR_LOG_STATE_INVALID",
        "message": (
            "The log service is not in the correct state to perform a requested action."
        ),
    },
    0x000019F4: {
        "code": "ERROR_LOG_PINNED",
        "message": "The log space cannot be reclaimed because the log is pinned.",
    },
    0x000019F5: {
        "code": "ERROR_LOG_METADATA_FLUSH_FAILED",
        "message": "The log metadata flush failed.",
    },
    0x000019F6: {
        "code": "ERROR_LOG_INCONSISTENT_SECURITY",
        "message": "Security on the log and its containers is inconsistent.",
    },
    0x000019F7: {
        "code": "ERROR_LOG_APPENDED_FLUSH_FAILED",
        "message": (
            "Records were appended to the log or reservation changes were made, but the"
            " log could not be flushed."
        ),
    },
    0x000019F8: {
        "code": "ERROR_LOG_PINNED_RESERVATION",
        "message": (
            "The log is pinned due to reservation consuming most of the log space. Free"
            " some reserved records to make space available."
        ),
    },
    0x00001A2C: {
        "code": "ERROR_INVALID_TRANSACTION",
        "message": (
            "The transaction handle associated with this operation is not valid."
        ),
    },
    0x00001A2D: {
        "code": "ERROR_TRANSACTION_NOT_ACTIVE",
        "message": (
            "The requested operation was made in the context of a transaction that is"
            " no longer active."
        ),
    },
    0x00001A2E: {
        "code": "ERROR_TRANSACTION_REQUEST_NOT_VALID",
        "message": (
            "The requested operation is not valid on the transaction object in its"
            " current state."
        ),
    },
    0x00001A2F: {
        "code": "ERROR_TRANSACTION_NOT_REQUESTED",
        "message": (
            "The caller has called a response API, but the response is not expected"
            " because the transaction manager did not issue the corresponding request"
            " to the caller."
        ),
    },
    0x00001A30: {
        "code": "ERROR_TRANSACTION_ALREADY_ABORTED",
        "message": (
            "It is too late to perform the requested operation because the transaction"
            " has already been aborted."
        ),
    },
    0x00001A31: {
        "code": "ERROR_TRANSACTION_ALREADY_COMMITTED",
        "message": (
            "It is too late to perform the requested operation because the transaction"
            " has already been committed."
        ),
    },
    0x00001A32: {
        "code": "ERROR_TM_INITIALIZATION_FAILED",
        "message": (
            "The transaction manager was unable to be successfully initialized."
            " Transacted operations are not supported."
        ),
    },
    0x00001A33: {
        "code": "ERROR_RESOURCEMANAGER_READ_ONLY",
        "message": (
            "The specified resource manager made no changes or updates to the resource"
            " under this transaction."
        ),
    },
    0x00001A34: {
        "code": "ERROR_TRANSACTION_NOT_JOINED",
        "message": (
            "The resource manager has attempted to prepare a transaction that it has"
            " not successfully joined."
        ),
    },
    0x00001A35: {
        "code": "ERROR_TRANSACTION_SUPERIOR_EXISTS",
        "message": (
            "The transaction object already has a superior enlistment, and the caller"
            " attempted an operation that would have created a new superior. Only a"
            " single superior enlistment is allowed."
        ),
    },
    0x00001A36: {
        "code": "ERROR_CRM_PROTOCOL_ALREADY_EXISTS",
        "message": (
            "The resource manager tried to register a protocol that already exists."
        ),
    },
    0x00001A37: {
        "code": "ERROR_TRANSACTION_PROPAGATION_FAILED",
        "message": "The attempt to propagate the transaction failed.",
    },
    0x00001A38: {
        "code": "ERROR_CRM_PROTOCOL_NOT_FOUND",
        "message": "The requested propagation protocol was not registered as a CRM.",
    },
    0x00001A39: {
        "code": "ERROR_TRANSACTION_INVALID_MARSHALL_BUFFER",
        "message": (
            "The buffer passed in to PushTransaction or PullTransaction is not in a"
            " valid format."
        ),
    },
    0x00001A3A: {
        "code": "ERROR_CURRENT_TRANSACTION_NOT_VALID",
        "message": (
            "The current transaction context associated with the thread is not a valid"
            " handle to a transaction object."
        ),
    },
    0x00001A3B: {
        "code": "ERROR_TRANSACTION_NOT_FOUND",
        "message": (
            "The specified transaction object could not be opened because it was not"
            " found."
        ),
    },
    0x00001A3C: {
        "code": "ERROR_RESOURCEMANAGER_NOT_FOUND",
        "message": (
            "The specified resource manager object could not be opened because it was"
            " not found."
        ),
    },
    0x00001A3D: {
        "code": "ERROR_ENLISTMENT_NOT_FOUND",
        "message": (
            "The specified enlistment object could not be opened because it was not"
            " found."
        ),
    },
    0x00001A3E: {
        "code": "ERROR_TRANSACTIONMANAGER_NOT_FOUND",
        "message": (
            "The specified transaction manager object could not be opened because it"
            " was not found."
        ),
    },
    0x00001A3F: {
        "code": "ERROR_TRANSACTIONMANAGER_NOT_ONLINE",
        "message": (
            "The specified resource manager was unable to create an enlistment because"
            " its associated transaction manager is not online."
        ),
    },
    0x00001A40: {
        "code": "ERROR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION",
        "message": (
            "The specified transaction manager was unable to create the objects"
            " contained in its log file in the ObjectB namespace. Therefore, the"
            " transaction manager was unable to recover."
        ),
    },
    0x00001A90: {
        "code": "ERROR_TRANSACTIONAL_CONFLICT",
        "message": (
            "The function attempted to use a name that is reserved for use by another"
            " transaction."
        ),
    },
    0x00001A91: {
        "code": "ERROR_RM_NOT_ACTIVE",
        "message": (
            "Transaction support within the specified file system resource manager is"
            " not started or was shut down due to an error."
        ),
    },
    0x00001A92: {
        "code": "ERROR_RM_METADATA_CORRUPT",
        "message": (
            "The metadata of the resource manager has been corrupted. The resource"
            " manager will not function."
        ),
    },
    0x00001A93: {
        "code": "ERROR_DIRECTORY_NOT_RM",
        "message": "The specified directory does not contain a resource manager.",
    },
    0x00001A95: {
        "code": "ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE",
        "message": (
            "The remote server or share does not support transacted file operations."
        ),
    },
    0x00001A96: {
        "code": "ERROR_LOG_RESIZE_INVALID_SIZE",
        "message": "The requested log size is invalid.",
    },
    0x00001A97: {
        "code": "ERROR_OBJECT_NO_LONGER_EXISTS",
        "message": (
            "The object (file, stream, link) corresponding to the handle has been"
            " deleted by a transaction savepoint rollback."
        ),
    },
    0x00001A98: {
        "code": "ERROR_STREAM_MINIVERSION_NOT_FOUND",
        "message": (
            "The specified file miniversion was not found for this transacted file"
            " open."
        ),
    },
    0x00001A99: {
        "code": "ERROR_STREAM_MINIVERSION_NOT_VALID",
        "message": (
            "The specified file miniversion was found but has been invalidated. The"
            " most likely cause is a transaction savepoint rollback."
        ),
    },
    0x00001A9A: {
        "code": "ERROR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION",
        "message": (
            "A miniversion can only be opened in the context of the transaction that"
            " created it."
        ),
    },
    0x00001A9B: {
        "code": "ERROR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT",
        "message": "It is not possible to open a miniversion with modify access.",
    },
    0x00001A9C: {
        "code": "ERROR_CANT_CREATE_MORE_STREAM_MINIVERSIONS",
        "message": (
            "It is not possible to create any more miniversions for this stream."
        ),
    },
    0x00001A9E: {
        "code": "ERROR_REMOTE_FILE_VERSION_MISMATCH",
        "message": (
            "The remote server sent mismatching version numbers or FID for a file"
            " opened with transactions."
        ),
    },
    0x00001A9F: {
        "code": "ERROR_HANDLE_NO_LONGER_VALID",
        "message": (
            "The handle has been invalidated by a transaction. The most likely cause is"
            " the presence of memory mapping on a file, or an open handle when the"
            " transaction ended or rolled back to savepoint."
        ),
    },
    0x00001AA0: {
        "code": "ERROR_NO_TXF_METADATA",
        "message": "There is no transaction metadata on the file.",
    },
    0x00001AA1: {
        "code": "ERROR_LOG_CORRUPTION_DETECTED",
        "message": "The log data is corrupt.",
    },
    0x00001AA2: {
        "code": "ERROR_CANT_RECOVER_WITH_HANDLE_OPEN",
        "message": "The file cannot be recovered because a handle is still open on it.",
    },
    0x00001AA3: {
        "code": "ERROR_RM_DISCONNECTED",
        "message": (
            "The transaction outcome is unavailable because the resource manager"
            " responsible for it is disconnected."
        ),
    },
    0x00001AA4: {
        "code": "ERROR_ENLISTMENT_NOT_SUPERIOR",
        "message": (
            "The request was rejected because the enlistment in question is not a"
            " superior enlistment."
        ),
    },
    0x00001AA5: {
        "code": "ERROR_RECOVERY_NOT_NEEDED",
        "message": (
            "The transactional resource manager is already consistent. Recovery is not"
            " needed."
        ),
    },
    0x00001AA6: {
        "code": "ERROR_RM_ALREADY_STARTED",
        "message": "The transactional resource manager has already been started.",
    },
    0x00001AA7: {
        "code": "ERROR_FILE_IDENTITY_NOT_PERSISTENT",
        "message": (
            "The file cannot be opened in a transaction because its identity depends on"
            " the outcome of an unresolved transaction."
        ),
    },
    0x00001AA8: {
        "code": "ERROR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY",
        "message": (
            "The operation cannot be performed because another transaction is depending"
            " on the fact that this property will not change."
        ),
    },
    0x00001AA9: {
        "code": "ERROR_CANT_CROSS_RM_BOUNDARY",
        "message": (
            "The operation would involve a single file with two transactional resource"
            " managers and is therefore not allowed."
        ),
    },
    0x00001AAA: {
        "code": "ERROR_TXF_DIR_NOT_EMPTY",
        "message": "The $Txf directory must be empty for this operation to succeed.",
    },
    0x00001AAB: {
        "code": "ERROR_INDOUBT_TRANSACTIONS_EXIST",
        "message": (
            "The operation would leave a transactional resource manager in an"
            " inconsistent state and is, therefore, not allowed."
        ),
    },
    0x00001AAC: {
        "code": "ERROR_TM_VOLATILE",
        "message": (
            "The operation could not be completed because the transaction manager does"
            " not have a log."
        ),
    },
    0x00001AAD: {
        "code": "ERROR_ROLLBACK_TIMER_EXPIRED",
        "message": (
            "A rollback could not be scheduled because a previously scheduled rollback"
            " has already been executed or is queued for execution."
        ),
    },
    0x00001AAE: {
        "code": "ERROR_TXF_ATTRIBUTE_CORRUPT",
        "message": (
            "The transactional metadata attribute on the file or directory is corrupt"
            " and unreadable."
        ),
    },
    0x00001AAF: {
        "code": "ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION",
        "message": (
            "The encryption operation could not be completed because a transaction is"
            " active."
        ),
    },
    0x00001AB0: {
        "code": "ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED",
        "message": "This object is not allowed to be opened in a transaction.",
    },
    0x00001AB1: {
        "code": "ERROR_LOG_GROWTH_FAILED",
        "message": (
            "An attempt to create space in the transactional resource manager's log"
            " failed. The failure status has been recorded in the event log."
        ),
    },
    0x00001AB2: {
        "code": "ERROR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE",
        "message": (
            "Memory mapping (creating a mapped section) to a remote file under a"
            " transaction is not supported."
        ),
    },
    0x00001AB3: {
        "code": "ERROR_TXF_METADATA_ALREADY_PRESENT",
        "message": (
            "Transaction metadata is already present on this file and cannot be"
            " superseded."
        ),
    },
    0x00001AB4: {
        "code": "ERROR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET",
        "message": (
            "A transaction scope could not be entered because the scope handler has not"
            " been initialized."
        ),
    },
    0x00001AB5: {
        "code": "ERROR_TRANSACTION_REQUIRED_PROMOTION",
        "message": (
            "Promotion was required to allow the resource manager to enlist, but the"
            " transaction was set to disallow it."
        ),
    },
    0x00001AB6: {
        "code": "ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION",
        "message": (
            "This file is open for modification in an unresolved transaction and can be"
            " opened for execution only by a transacted reader."
        ),
    },
    0x00001AB7: {
        "code": "ERROR_TRANSACTIONS_NOT_FROZEN",
        "message": (
            "The request to thaw frozen transactions was ignored because transactions"
            " were not previously frozen."
        ),
    },
    0x00001AB8: {
        "code": "ERROR_TRANSACTION_FREEZE_IN_PROGRESS",
        "message": (
            "Transactions cannot be frozen because a freeze is already in progress."
        ),
    },
    0x00001AB9: {
        "code": "ERROR_NOT_SNAPSHOT_VOLUME",
        "message": (
            "The target volume is not a snapshot volume. This operation is only valid"
            " on a volume mounted as a snapshot."
        ),
    },
    0x00001ABA: {
        "code": "ERROR_NO_SAVEPOINT_WITH_OPEN_FILES",
        "message": (
            "The savepoint operation failed because files are open on the transaction."
            " This is not permitted."
        ),
    },
    0x00001ABB: {
        "code": "ERROR_DATA_LOST_REPAIR",
        "message": (
            "Windows has discovered corruption in a file, and that file has since been"
            " repaired. Data loss might have occurred."
        ),
    },
    0x00001ABC: {
        "code": "ERROR_SPARSE_NOT_ALLOWED_IN_TRANSACTION",
        "message": (
            "The sparse operation could not be completed because a transaction is"
            " active on the file."
        ),
    },
    0x00001ABD: {
        "code": "ERROR_TM_IDENTITY_MISMATCH",
        "message": (
            "The call to create a transaction manager object failed because the Tm"
            " Identity stored in the logfile does not match the Tm Identity that was"
            " passed in as an argument."
        ),
    },
    0x00001ABE: {
        "code": "ERROR_FLOATED_SECTION",
        "message": (
            "I/O was attempted on a section object that has been floated as a result of"
            " a transaction ending. There is no valid data."
        ),
    },
    0x00001ABF: {
        "code": "ERROR_CANNOT_ACCEPT_TRANSACTED_WORK",
        "message": (
            "The transactional resource manager cannot currently accept transacted work"
            " due to a transient condition, such as low resources."
        ),
    },
    0x00001AC0: {
        "code": "ERROR_CANNOT_ABORT_TRANSACTIONS",
        "message": (
            "The transactional resource manager had too many transactions outstanding"
            " that could not be aborted. The transactional resource manager has been"
            " shut down."
        ),
    },
    0x00001B59: {
        "code": "ERROR_CTX_WINSTATION_NAME_INVALID",
        "message": "The specified session name is invalid.",
    },
    0x00001B5A: {
        "code": "ERROR_CTX_INVALID_PD",
        "message": "The specified protocol driver is invalid.",
    },
    0x00001B5B: {
        "code": "ERROR_CTX_PD_NOT_FOUND",
        "message": "The specified protocol driver was not found in the system path.",
    },
    0x00001B5C: {
        "code": "ERROR_CTX_WD_NOT_FOUND",
        "message": (
            "The specified terminal connection driver was not found in the system path."
        ),
    },
    0x00001B5D: {
        "code": "ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY",
        "message": (
            "A registry key for event logging could not be created for this session."
        ),
    },
    0x00001B5E: {
        "code": "ERROR_CTX_SERVICE_NAME_COLLISION",
        "message": "A service with the same name already exists on the system.",
    },
    0x00001B5F: {
        "code": "ERROR_CTX_CLOSE_PENDING",
        "message": "A close operation is pending on the session.",
    },
    0x00001B60: {
        "code": "ERROR_CTX_NO_OUTBUF",
        "message": "There are no free output buffers available.",
    },
    0x00001B61: {
        "code": "ERROR_CTX_MODEM_INF_NOT_FOUND",
        "message": "The MODEM.INF file was not found.",
    },
    0x00001B62: {
        "code": "ERROR_CTX_INVALID_MODEMNAME",
        "message": "The modem name was not found in the MODEM.INF file.",
    },
    0x00001B63: {
        "code": "ERROR_CTX_MODEM_RESPONSE_ERROR",
        "message": (
            "The modem did not accept the command sent to it. Verify that the"
            " configured modem name matches the attached modem."
        ),
    },
    0x00001B64: {
        "code": "ERROR_CTX_MODEM_RESPONSE_TIMEOUT",
        "message": (
            "The modem did not respond to the command sent to it. Verify that the modem"
            " is properly cabled and turned on."
        ),
    },
    0x00001B65: {
        "code": "ERROR_CTX_MODEM_RESPONSE_NO_CARRIER",
        "message": (
            "Carrier detect has failed or carrier has been dropped due to disconnect."
        ),
    },
    0x00001B66: {
        "code": "ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE",
        "message": (
            "Dial tone not detected within the required time. Verify that the phone"
            " cable is properly attached and functional."
        ),
    },
    0x00001B67: {
        "code": "ERROR_CTX_MODEM_RESPONSE_BUSY",
        "message": "Busy signal detected at remote site on callback.",
    },
    0x00001B68: {
        "code": "ERROR_CTX_MODEM_RESPONSE_VOICE",
        "message": "Voice detected at remote site on callback.",
    },
    0x00001B69: {"code": "ERROR_CTX_TD_ERROR", "message": "Transport driver error."},
    0x00001B6E: {
        "code": "ERROR_CTX_WINSTATION_NOT_FOUND",
        "message": "The specified session cannot be found.",
    },
    0x00001B6F: {
        "code": "ERROR_CTX_WINSTATION_ALREADY_EXISTS",
        "message": "The specified session name is already in use.",
    },
    0x00001B70: {
        "code": "ERROR_CTX_WINSTATION_BUSY",
        "message": (
            "The requested operation cannot be completed because the terminal"
            " connection is currently busy processing a connect, disconnect, reset, or"
            " delete operation."
        ),
    },
    0x00001B71: {
        "code": "ERROR_CTX_BAD_VIDEO_MODE",
        "message": (
            "An attempt has been made to connect to a session whose video mode is not"
            " supported by the current client."
        ),
    },
    0x00001B7B: {
        "code": "ERROR_CTX_GRAPHICS_INVALID",
        "message": (
            "The application attempted to enable DOS graphics mode. DOS graphics mode"
            " is not supported."
        ),
    },
    0x00001B7D: {
        "code": "ERROR_CTX_LOGON_DISABLED",
        "message": (
            "Your interactive logon privilege has been disabled. Contact your"
            " administrator."
        ),
    },
    0x00001B7E: {
        "code": "ERROR_CTX_NOT_CONSOLE",
        "message": (
            "The requested operation can be performed only on the system console. This"
            " is most often the result of a driver or system DLL requiring direct"
            " console access."
        ),
    },
    0x00001B80: {
        "code": "ERROR_CTX_CLIENT_QUERY_TIMEOUT",
        "message": "The client failed to respond to the server connect message.",
    },
    0x00001B81: {
        "code": "ERROR_CTX_CONSOLE_DISCONNECT",
        "message": "Disconnecting the console session is not supported.",
    },
    0x00001B82: {
        "code": "ERROR_CTX_CONSOLE_CONNECT",
        "message": (
            "Reconnecting a disconnected session to the console is not supported."
        ),
    },
    0x00001B84: {
        "code": "ERROR_CTX_SHADOW_DENIED",
        "message": "The request to control another session remotely was denied.",
    },
    0x00001B85: {
        "code": "ERROR_CTX_WINSTATION_ACCESS_DENIED",
        "message": "The requested session access is denied.",
    },
    0x00001B89: {
        "code": "ERROR_CTX_INVALID_WD",
        "message": "The specified terminal connection driver is invalid.",
    },
    0x00001B8A: {
        "code": "ERROR_CTX_SHADOW_INVALID",
        "message": (
            "The requested session cannot be controlled remotely. This might be because"
            " the session is disconnected or does not currently have a user logged on."
        ),
    },
    0x00001B8B: {
        "code": "ERROR_CTX_SHADOW_DISABLED",
        "message": "The requested session is not configured to allow remote control.",
    },
    0x00001B8C: {
        "code": "ERROR_CTX_CLIENT_LICENSE_IN_USE",
        "message": (
            "Your request to connect to this terminal server has been rejected. Your"
            " terminal server client license number is currently being used by another"
            " user. Call your system administrator to obtain a unique license number."
        ),
    },
    0x00001B8D: {
        "code": "ERROR_CTX_CLIENT_LICENSE_NOT_SET",
        "message": (
            "Your request to connect to this terminal server has been rejected. Your"
            " terminal server client license number has not been entered for this copy"
            " of the terminal server client. Contact your system administrator."
        ),
    },
    0x00001B8E: {
        "code": "ERROR_CTX_LICENSE_NOT_AVAILABLE",
        "message": (
            "The number of connections to this computer is limited and all connections"
            " are in use right now. Try connecting later or contact your system"
            " administrator."
        ),
    },
    0x00001B8F: {
        "code": "ERROR_CTX_LICENSE_CLIENT_INVALID",
        "message": (
            "The client you are using is not licensed to use this system. Your logon"
            " request is denied."
        ),
    },
    0x00001B90: {
        "code": "ERROR_CTX_LICENSE_EXPIRED",
        "message": "The system license has expired. Your logon request is denied.",
    },
    0x00001B91: {
        "code": "ERROR_CTX_SHADOW_NOT_RUNNING",
        "message": (
            "Remote control could not be terminated because the specified session is"
            " not currently being remotely controlled."
        ),
    },
    0x00001B92: {
        "code": "ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE",
        "message": (
            "The remote control of the console was terminated because the display mode"
            " was changed. Changing the display mode in a remote control session is not"
            " supported."
        ),
    },
    0x00001B93: {
        "code": "ERROR_ACTIVATION_COUNT_EXCEEDED",
        "message": (
            "Activation has already been reset the maximum number of times for this"
            " installation. Your activation timer will not be cleared."
        ),
    },
    0x00001B94: {
        "code": "ERROR_CTX_WINSTATIONS_DISABLED",
        "message": "Remote logons are currently disabled.",
    },
    0x00001B95: {
        "code": "ERROR_CTX_ENCRYPTION_LEVEL_REQUIRED",
        "message": (
            "You do not have the proper encryption level to access this session."
        ),
    },
    0x00001B96: {
        "code": "ERROR_CTX_SESSION_IN_USE",
        "message": (
            "The user %s\\%s is currently logged on to this computer. Only the current"
            " user or an administrator can log on to this computer."
        ),
    },
    0x00001B97: {
        "code": "ERROR_CTX_NO_FORCE_LOGOFF",
        "message": (
            "The user %s\\%s is already logged on to the console of this computer. You"
            " do not have permission to log in at this time. To resolve this issue,"
            " contact %s\\%s and have them log off."
        ),
    },
    0x00001B98: {
        "code": "ERROR_CTX_ACCOUNT_RESTRICTION",
        "message": "Unable to log you on because of an account restriction.",
    },
    0x00001B99: {
        "code": "ERROR_RDP_PROTOCOL_ERROR",
        "message": (
            "The RDP component %2 detected an error in the protocol stream and has"
            " disconnected the client."
        ),
    },
    0x00001B9A: {
        "code": "ERROR_CTX_CDM_CONNECT",
        "message": (
            "The Client Drive Mapping Service has connected on terminal connection."
        ),
    },
    0x00001B9B: {
        "code": "ERROR_CTX_CDM_DISCONNECT",
        "message": (
            "The Client Drive Mapping Service has disconnected on terminal connection."
        ),
    },
    0x00001B9C: {
        "code": "ERROR_CTX_SECURITY_LAYER_ERROR",
        "message": (
            "The terminal server security layer detected an error in the protocol"
            " stream and has disconnected the client."
        ),
    },
    0x00001B9D: {
        "code": "ERROR_TS_INCOMPATIBLE_SESSIONS",
        "message": "The target session is incompatible with the current session.",
    },
    0x00001F41: {
        "code": "FRS_ERR_INVALID_API_SEQUENCE",
        "message": "The file replication service API was called incorrectly.",
    },
    0x00001F42: {
        "code": "FRS_ERR_STARTING_SERVICE",
        "message": "The file replication service cannot be started.",
    },
    0x00001F43: {
        "code": "FRS_ERR_STOPPING_SERVICE",
        "message": "The file replication service cannot be stopped.",
    },
    0x00001F44: {
        "code": "FRS_ERR_INTERNAL_API",
        "message": (
            "The file replication service API terminated the request. The event log"
            " might contain more information."
        ),
    },
    0x00001F45: {
        "code": "FRS_ERR_INTERNAL",
        "message": (
            "The file replication service terminated the request. The event log might"
            " contain more information."
        ),
    },
    0x00001F46: {
        "code": "FRS_ERR_SERVICE_COMM",
        "message": (
            "The file replication service cannot be contacted. The event log might"
            " contain more information."
        ),
    },
    0x00001F47: {
        "code": "FRS_ERR_INSUFFICIENT_PRIV",
        "message": (
            "The file replication service cannot satisfy the request because the user"
            " has insufficient privileges. The event log might contain more"
            " information."
        ),
    },
    0x00001F48: {
        "code": "FRS_ERR_AUTHENTICATION",
        "message": (
            "The file replication service cannot satisfy the request because"
            " authenticated RPC is not available. The event log might contain more"
            " information."
        ),
    },
    0x00001F49: {
        "code": "FRS_ERR_PARENT_INSUFFICIENT_PRIV",
        "message": (
            "The file replication service cannot satisfy the request because the user"
            " has insufficient privileges on the domain controller. The event log might"
            " contain more information."
        ),
    },
    0x00001F4A: {
        "code": "FRS_ERR_PARENT_AUTHENTICATION",
        "message": (
            "The file replication service cannot satisfy the request because"
            " authenticated RPC is not available on the domain controller. The event"
            " log might contain more information."
        ),
    },
    0x00001F4B: {
        "code": "FRS_ERR_CHILD_TO_PARENT_COMM",
        "message": (
            "The file replication service cannot communicate with the file replication"
            " service on the domain controller. The event log might contain more"
            " information."
        ),
    },
    0x00001F4C: {
        "code": "FRS_ERR_PARENT_TO_CHILD_COMM",
        "message": (
            "The file replication service on the domain controller cannot communicate"
            " with the file replication service on this computer. The event log might"
            " contain more information."
        ),
    },
    0x00001F4D: {
        "code": "FRS_ERR_SYSVOL_POPULATE",
        "message": (
            "The file replication service cannot populate the system volume because of"
            " an internal error. The event log might contain more information."
        ),
    },
    0x00001F4E: {
        "code": "FRS_ERR_SYSVOL_POPULATE_TIMEOUT",
        "message": (
            "The file replication service cannot populate the system volume because of"
            " an internal time-out. The event log might contain more information."
        ),
    },
    0x00001F4F: {
        "code": "FRS_ERR_SYSVOL_IS_BUSY",
        "message": (
            "The file replication service cannot process the request. The system volume"
            " is busy with a previous request."
        ),
    },
    0x00001F50: {
        "code": "FRS_ERR_SYSVOL_DEMOTE",
        "message": (
            "The file replication service cannot stop replicating the system volume"
            " because of an internal error. The event log might contain more"
            " information."
        ),
    },
    0x00001F51: {
        "code": "FRS_ERR_INVALID_SERVICE_PARAMETER",
        "message": "The file replication service detected an invalid parameter.",
    },
    0x00002008: {
        "code": "ERROR_DS_NOT_INSTALLED",
        "message": (
            "An error occurred while installing the directory service. For more"
            " information, see the event log."
        ),
    },
    0x00002009: {
        "code": "ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY",
        "message": "The directory service evaluated group memberships locally.",
    },
    0x0000200A: {
        "code": "ERROR_DS_NO_ATTRIBUTE_OR_VALUE",
        "message": "The specified directory service attribute or value does not exist.",
    },
    0x0000200B: {
        "code": "ERROR_DS_INVALID_ATTRIBUTE_SYNTAX",
        "message": (
            "The attribute syntax specified to the directory service is invalid."
        ),
    },
    0x0000200C: {
        "code": "ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED",
        "message": (
            "The attribute type specified to the directory service is not defined."
        ),
    },
    0x0000200D: {
        "code": "ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS",
        "message": "The specified directory service attribute or value already exists.",
    },
    0x0000200E: {"code": "ERROR_DS_BUSY", "message": "The directory service is busy."},
    0x0000200F: {
        "code": "ERROR_DS_UNAVAILABLE",
        "message": "The directory service is unavailable.",
    },
    0x00002010: {
        "code": "ERROR_DS_NO_RIDS_ALLOCATED",
        "message": (
            "The directory service was unable to allocate a relative identifier."
        ),
    },
    0x00002011: {
        "code": "ERROR_DS_NO_MORE_RIDS",
        "message": (
            "The directory service has exhausted the pool of relative identifiers."
        ),
    },
    0x00002012: {
        "code": "ERROR_DS_INCORRECT_ROLE_OWNER",
        "message": (
            "The requested operation could not be performed because the directory"
            " service is not the master for that type of operation."
        ),
    },
    0x00002013: {
        "code": "ERROR_DS_RIDMGR_INIT_ERROR",
        "message": (
            "The directory service was unable to initialize the subsystem that"
            " allocates relative identifiers."
        ),
    },
    0x00002014: {
        "code": "ERROR_DS_OBJ_CLASS_VIOLATION",
        "message": (
            "The requested operation did not satisfy one or more constraints associated"
            " with the class of the object."
        ),
    },
    0x00002015: {
        "code": "ERROR_DS_CANT_ON_NON_LEAF",
        "message": (
            "The directory service can perform the requested operation only on a leaf"
            " object."
        ),
    },
    0x00002016: {
        "code": "ERROR_DS_CANT_ON_RDN",
        "message": (
            "The directory service cannot perform the requested operation on the"
            " relative distinguished name (RDN) attribute of an object."
        ),
    },
    0x00002017: {
        "code": "ERROR_DS_CANT_MOD_OBJ_CLASS",
        "message": (
            "The directory service detected an attempt to modify the object class of an"
            " object."
        ),
    },
    0x00002018: {
        "code": "ERROR_DS_CROSS_DOM_MOVE_ERROR",
        "message": "The requested cross-domain move operation could not be performed.",
    },
    0x00002019: {
        "code": "ERROR_DS_GC_NOT_AVAILABLE",
        "message": "Unable to contact the global catalog (GC) server.",
    },
    0x0000201A: {
        "code": "ERROR_SHARED_POLICY",
        "message": "The policy object is shared and can only be modified at the root.",
    },
    0x0000201B: {
        "code": "ERROR_POLICY_OBJECT_NOT_FOUND",
        "message": "The policy object does not exist.",
    },
    0x0000201C: {
        "code": "ERROR_POLICY_ONLY_IN_DS",
        "message": "The requested policy information is only in the directory service.",
    },
    0x0000201D: {
        "code": "ERROR_PROMOTION_ACTIVE",
        "message": "A domain controller promotion is currently active.",
    },
    0x0000201E: {
        "code": "ERROR_NO_PROMOTION_ACTIVE",
        "message": "A domain controller promotion is not currently active.",
    },
    0x00002020: {
        "code": "ERROR_DS_OPERATIONS_ERROR",
        "message": "An operations error occurred.",
    },
    0x00002021: {
        "code": "ERROR_DS_PROTOCOL_ERROR",
        "message": "A protocol error occurred.",
    },
    0x00002022: {
        "code": "ERROR_DS_TIMELIMIT_EXCEEDED",
        "message": "The time limit for this request was exceeded.",
    },
    0x00002023: {
        "code": "ERROR_DS_SIZELIMIT_EXCEEDED",
        "message": "The size limit for this request was exceeded.",
    },
    0x00002024: {
        "code": "ERROR_DS_ADMIN_LIMIT_EXCEEDED",
        "message": "The administrative limit for this request was exceeded.",
    },
    0x00002025: {
        "code": "ERROR_DS_COMPARE_FALSE",
        "message": "The compare response was false.",
    },
    0x00002026: {
        "code": "ERROR_DS_COMPARE_TRUE",
        "message": "The compare response was true.",
    },
    0x00002027: {
        "code": "ERROR_DS_AUTH_METHOD_NOT_SUPPORTED",
        "message": (
            "The requested authentication method is not supported by the server."
        ),
    },
    0x00002028: {
        "code": "ERROR_DS_STRONG_AUTH_REQUIRED",
        "message": "A more secure authentication method is required for this server.",
    },
    0x00002029: {
        "code": "ERROR_DS_INAPPROPRIATE_AUTH",
        "message": "Inappropriate authentication.",
    },
    0x0000202A: {
        "code": "ERROR_DS_AUTH_UNKNOWN",
        "message": "The authentication mechanism is unknown.",
    },
    0x0000202B: {
        "code": "ERROR_DS_REFERRAL",
        "message": "A referral was returned from the server.",
    },
    0x0000202C: {
        "code": "ERROR_DS_UNAVAILABLE_CRIT_EXTENSION",
        "message": "The server does not support the requested critical extension.",
    },
    0x0000202D: {
        "code": "ERROR_DS_CONFIDENTIALITY_REQUIRED",
        "message": "This request requires a secure connection.",
    },
    0x0000202E: {
        "code": "ERROR_DS_INAPPROPRIATE_MATCHING",
        "message": "Inappropriate matching.",
    },
    0x0000202F: {
        "code": "ERROR_DS_CONSTRAINT_VIOLATION",
        "message": "A constraint violation occurred.",
    },
    0x00002030: {
        "code": "ERROR_DS_NO_SUCH_OBJECT",
        "message": "There is no such object on the server.",
    },
    0x00002031: {
        "code": "ERROR_DS_ALIAS_PROBLEM",
        "message": "There is an alias problem.",
    },
    0x00002032: {
        "code": "ERROR_DS_INVALID_DN_SYNTAX",
        "message": "An invalid dn syntax has been specified.",
    },
    0x00002033: {"code": "ERROR_DS_IS_LEAF", "message": "The object is a leaf object."},
    0x00002034: {
        "code": "ERROR_DS_ALIAS_DEREF_PROBLEM",
        "message": "There is an alias dereferencing problem.",
    },
    0x00002035: {
        "code": "ERROR_DS_UNWILLING_TO_PERFORM",
        "message": "The server is unwilling to process the request.",
    },
    0x00002036: {
        "code": "ERROR_DS_LOOP_DETECT",
        "message": "A loop has been detected.",
    },
    0x00002037: {
        "code": "ERROR_DS_NAMING_VIOLATION",
        "message": "There is a naming violation.",
    },
    0x00002038: {
        "code": "ERROR_DS_OBJECT_RESULTS_TOO_LARGE",
        "message": "The result set is too large.",
    },
    0x00002039: {
        "code": "ERROR_DS_AFFECTS_MULTIPLE_DSAS",
        "message": "The operation affects multiple DSAs.",
    },
    0x0000203A: {
        "code": "ERROR_DS_SERVER_DOWN",
        "message": "The server is not operational.",
    },
    0x0000203B: {
        "code": "ERROR_DS_LOCAL_ERROR",
        "message": "A local error has occurred.",
    },
    0x0000203C: {
        "code": "ERROR_DS_ENCODING_ERROR",
        "message": "An encoding error has occurred.",
    },
    0x0000203D: {
        "code": "ERROR_DS_DECODING_ERROR",
        "message": "A decoding error has occurred.",
    },
    0x0000203E: {
        "code": "ERROR_DS_FILTER_UNKNOWN",
        "message": "The search filter cannot be recognized.",
    },
    0x0000203F: {
        "code": "ERROR_DS_PARAM_ERROR",
        "message": "One or more parameters are illegal.",
    },
    0x00002040: {
        "code": "ERROR_DS_NOT_SUPPORTED",
        "message": "The specified method is not supported.",
    },
    0x00002041: {
        "code": "ERROR_DS_NO_RESULTS_RETURNED",
        "message": "No results were returned.",
    },
    0x00002042: {
        "code": "ERROR_DS_CONTROL_NOT_FOUND",
        "message": "The specified control is not supported by the server.",
    },
    0x00002043: {
        "code": "ERROR_DS_CLIENT_LOOP",
        "message": "A referral loop was detected by the client.",
    },
    0x00002044: {
        "code": "ERROR_DS_REFERRAL_LIMIT_EXCEEDED",
        "message": "The preset referral limit was exceeded.",
    },
    0x00002045: {
        "code": "ERROR_DS_SORT_CONTROL_MISSING",
        "message": "The search requires a SORT control.",
    },
    0x00002046: {
        "code": "ERROR_DS_OFFSET_RANGE_ERROR",
        "message": "The search results exceed the offset range specified.",
    },
    0x0000206D: {
        "code": "ERROR_DS_ROOT_MUST_BE_NC",
        "message": (
            "The root object must be the head of a naming context. The root object"
            " cannot have an instantiated parent."
        ),
    },
    0x0000206E: {
        "code": "ERROR_DS_ADD_REPLICA_INHIBITED",
        "message": (
            "The add replica operation cannot be performed. The naming context must be"
            " writable to create the replica."
        ),
    },
    0x0000206F: {
        "code": "ERROR_DS_ATT_NOT_DEF_IN_SCHEMA",
        "message": (
            "A reference to an attribute that is not defined in the schema occurred."
        ),
    },
    0x00002070: {
        "code": "ERROR_DS_MAX_OBJ_SIZE_EXCEEDED",
        "message": "The maximum size of an object has been exceeded.",
    },
    0x00002071: {
        "code": "ERROR_DS_OBJ_STRING_NAME_EXISTS",
        "message": (
            "An attempt was made to add an object to the directory with a name that is"
            " already in use."
        ),
    },
    0x00002072: {
        "code": "ERROR_DS_NO_RDN_DEFINED_IN_SCHEMA",
        "message": (
            "An attempt was made to add an object of a class that does not have an RDN"
            " defined in the schema."
        ),
    },
    0x00002073: {
        "code": "ERROR_DS_RDN_DOESNT_MATCH_SCHEMA",
        "message": (
            "An attempt was made to add an object using an RDN that is not the RDN"
            " defined in the schema."
        ),
    },
    0x00002074: {
        "code": "ERROR_DS_NO_REQUESTED_ATTS_FOUND",
        "message": "None of the requested attributes were found on the objects.",
    },
    0x00002075: {
        "code": "ERROR_DS_USER_BUFFER_TO_SMALL",
        "message": "The user buffer is too small.",
    },
    0x00002076: {
        "code": "ERROR_DS_ATT_IS_NOT_ON_OBJ",
        "message": (
            "The attribute specified in the operation is not present on the object."
        ),
    },
    0x00002077: {
        "code": "ERROR_DS_ILLEGAL_MOD_OPERATION",
        "message": (
            "Illegal modify operation. Some aspect of the modification is not"
            " permitted."
        ),
    },
    0x00002078: {
        "code": "ERROR_DS_OBJ_TOO_LARGE",
        "message": "The specified object is too large.",
    },
    0x00002079: {
        "code": "ERROR_DS_BAD_INSTANCE_TYPE",
        "message": "The specified instance type is not valid.",
    },
    0x0000207A: {
        "code": "ERROR_DS_MASTERDSA_REQUIRED",
        "message": "The operation must be performed at a master DSA.",
    },
    0x0000207B: {
        "code": "ERROR_DS_OBJECT_CLASS_REQUIRED",
        "message": "The object class attribute must be specified.",
    },
    0x0000207C: {
        "code": "ERROR_DS_MISSING_REQUIRED_ATT",
        "message": "A required attribute is missing.",
    },
    0x0000207D: {
        "code": "ERROR_DS_ATT_NOT_DEF_FOR_CLASS",
        "message": (
            "An attempt was made to modify an object to include an attribute that is"
            " not legal for its class."
        ),
    },
    0x0000207E: {
        "code": "ERROR_DS_ATT_ALREADY_EXISTS",
        "message": "The specified attribute is already present on the object.",
    },
    0x00002080: {
        "code": "ERROR_DS_CANT_ADD_ATT_VALUES",
        "message": "The specified attribute is not present, or has no values.",
    },
    0x00002081: {
        "code": "ERROR_DS_SINGLE_VALUE_CONSTRAINT",
        "message": (
            "Multiple values were specified for an attribute that can have only one"
            " value."
        ),
    },
    0x00002082: {
        "code": "ERROR_DS_RANGE_CONSTRAINT",
        "message": (
            "A value for the attribute was not in the acceptable range of values."
        ),
    },
    0x00002083: {
        "code": "ERROR_DS_ATT_VAL_ALREADY_EXISTS",
        "message": "The specified value already exists.",
    },
    0x00002084: {
        "code": "ERROR_DS_CANT_REM_MISSING_ATT",
        "message": (
            "The attribute cannot be removed because it is not present on the object."
        ),
    },
    0x00002085: {
        "code": "ERROR_DS_CANT_REM_MISSING_ATT_VAL",
        "message": (
            "The attribute value cannot be removed because it is not present on the"
            " object."
        ),
    },
    0x00002086: {
        "code": "ERROR_DS_ROOT_CANT_BE_SUBREF",
        "message": "The specified root object cannot be a subreference.",
    },
    0x00002087: {
        "code": "ERROR_DS_NO_CHAINING",
        "message": "Chaining is not permitted.",
    },
    0x00002088: {
        "code": "ERROR_DS_NO_CHAINED_EVAL",
        "message": "Chained evaluation is not permitted.",
    },
    0x00002089: {
        "code": "ERROR_DS_NO_PARENT_OBJECT",
        "message": (
            "The operation could not be performed because the object's parent is either"
            " uninstantiated or deleted."
        ),
    },
    0x0000208A: {
        "code": "ERROR_DS_PARENT_IS_AN_ALIAS",
        "message": (
            "Having a parent that is an alias is not permitted. Aliases are leaf"
            " objects."
        ),
    },
    0x0000208B: {
        "code": "ERROR_DS_CANT_MIX_MASTER_AND_REPS",
        "message": (
            "The object and parent must be of the same type, either both masters or"
            " both replicas."
        ),
    },
    0x0000208C: {
        "code": "ERROR_DS_CHILDREN_EXIST",
        "message": (
            "The operation cannot be performed because child objects exist. This"
            " operation can only be performed on a leaf object."
        ),
    },
    0x0000208D: {
        "code": "ERROR_DS_OBJ_NOT_FOUND",
        "message": "Directory object not found.",
    },
    0x0000208E: {
        "code": "ERROR_DS_ALIASED_OBJ_MISSING",
        "message": "The aliased object is missing.",
    },
    0x0000208F: {
        "code": "ERROR_DS_BAD_NAME_SYNTAX",
        "message": "The object name has bad syntax.",
    },
    0x00002090: {
        "code": "ERROR_DS_ALIAS_POINTS_TO_ALIAS",
        "message": "An alias is not permitted to refer to another alias.",
    },
    0x00002091: {
        "code": "ERROR_DS_CANT_DEREF_ALIAS",
        "message": "The alias cannot be dereferenced.",
    },
    0x00002092: {
        "code": "ERROR_DS_OUT_OF_SCOPE",
        "message": "The operation is out of scope.",
    },
    0x00002093: {
        "code": "ERROR_DS_OBJECT_BEING_REMOVED",
        "message": (
            "The operation cannot continue because the object is in the process of"
            " being removed."
        ),
    },
    0x00002094: {
        "code": "ERROR_DS_CANT_DELETE_DSA_OBJ",
        "message": "The DSA object cannot be deleted.",
    },
    0x00002095: {
        "code": "ERROR_DS_GENERIC_ERROR",
        "message": "A directory service error has occurred.",
    },
    0x00002096: {
        "code": "ERROR_DS_DSA_MUST_BE_INT_MASTER",
        "message": (
            "The operation can only be performed on an internal master DSA object."
        ),
    },
    0x00002097: {
        "code": "ERROR_DS_CLASS_NOT_DSA",
        "message": "The object must be of class DSA.",
    },
    0x00002098: {
        "code": "ERROR_DS_INSUFF_ACCESS_RIGHTS",
        "message": "Insufficient access rights to perform the operation.",
    },
    0x00002099: {
        "code": "ERROR_DS_ILLEGAL_SUPERIOR",
        "message": (
            "The object cannot be added because the parent is not on the list of"
            " possible superiors."
        ),
    },
    0x0000209A: {
        "code": "ERROR_DS_ATTRIBUTE_OWNED_BY_SAM",
        "message": (
            "Access to the attribute is not permitted because the attribute is owned by"
            " the SAM."
        ),
    },
    0x0000209B: {
        "code": "ERROR_DS_NAME_TOO_MANY_PARTS",
        "message": "The name has too many parts.",
    },
    0x0000209C: {"code": "ERROR_DS_NAME_TOO_LONG", "message": "The name is too long."},
    0x0000209D: {
        "code": "ERROR_DS_NAME_VALUE_TOO_LONG",
        "message": "The name value is too long.",
    },
    0x0000209E: {
        "code": "ERROR_DS_NAME_UNPARSEABLE",
        "message": "The directory service encountered an error parsing a name.",
    },
    0x0000209F: {
        "code": "ERROR_DS_NAME_TYPE_UNKNOWN",
        "message": "The directory service cannot get the attribute type for a name.",
    },
    0x000020A0: {
        "code": "ERROR_DS_NOT_AN_OBJECT",
        "message": (
            "The name does not identify an object; the name identifies a phantom."
        ),
    },
    0x000020A1: {
        "code": "ERROR_DS_SEC_DESC_TOO_SHORT",
        "message": "The security descriptor is too short.",
    },
    0x000020A2: {
        "code": "ERROR_DS_SEC_DESC_INVALID",
        "message": "The security descriptor is invalid.",
    },
    0x000020A3: {
        "code": "ERROR_DS_NO_DELETED_NAME",
        "message": "Failed to create name for deleted object.",
    },
    0x000020A4: {
        "code": "ERROR_DS_SUBREF_MUST_HAVE_PARENT",
        "message": "The parent of a new subreference must exist.",
    },
    0x000020A5: {
        "code": "ERROR_DS_NCNAME_MUST_BE_NC",
        "message": "The object must be a naming context.",
    },
    0x000020A6: {
        "code": "ERROR_DS_CANT_ADD_SYSTEM_ONLY",
        "message": (
            "It is not permitted to add an attribute that is owned by the system."
        ),
    },
    0x000020A7: {
        "code": "ERROR_DS_CLASS_MUST_BE_CONCRETE",
        "message": (
            "The class of the object must be structural; you cannot instantiate an"
            " abstract class."
        ),
    },
    0x000020A8: {
        "code": "ERROR_DS_INVALID_DMD",
        "message": "The schema object could not be found.",
    },
    0x000020A9: {
        "code": "ERROR_DS_OBJ_GUID_EXISTS",
        "message": "A local object with this GUID (dead or alive) already exists.",
    },
    0x000020AA: {
        "code": "ERROR_DS_NOT_ON_BACKLINK",
        "message": "The operation cannot be performed on a back link.",
    },
    0x000020AB: {
        "code": "ERROR_DS_NO_CROSSREF_FOR_NC",
        "message": (
            "The cross-reference for the specified naming context could not be found."
        ),
    },
    0x000020AC: {
        "code": "ERROR_DS_SHUTTING_DOWN",
        "message": (
            "The operation could not be performed because the directory service is"
            " shutting down."
        ),
    },
    0x000020AD: {
        "code": "ERROR_DS_UNKNOWN_OPERATION",
        "message": "The directory service request is invalid.",
    },
    0x000020AE: {
        "code": "ERROR_DS_INVALID_ROLE_OWNER",
        "message": "The role owner attribute could not be read.",
    },
    0x000020AF: {
        "code": "ERROR_DS_COULDNT_CONTACT_FSMO",
        "message": (
            "The requested Flexible Single Master Operations (FSMO) operation failed."
            " The current FSMO holder could not be contacted."
        ),
    },
    0x000020B0: {
        "code": "ERROR_DS_CROSS_NC_DN_RENAME",
        "message": (
            "Modification of a distinguished name across a naming context is not"
            " permitted."
        ),
    },
    0x000020B1: {
        "code": "ERROR_DS_CANT_MOD_SYSTEM_ONLY",
        "message": (
            "The attribute cannot be modified because it is owned by the system."
        ),
    },
    0x000020B2: {
        "code": "ERROR_DS_REPLICATOR_ONLY",
        "message": "Only the replicator can perform this function.",
    },
    0x000020B3: {
        "code": "ERROR_DS_OBJ_CLASS_NOT_DEFINED",
        "message": "The specified class is not defined.",
    },
    0x000020B4: {
        "code": "ERROR_DS_OBJ_CLASS_NOT_SUBCLASS",
        "message": "The specified class is not a subclass.",
    },
    0x000020B5: {
        "code": "ERROR_DS_NAME_REFERENCE_INVALID",
        "message": "The name reference is invalid.",
    },
    0x000020B6: {
        "code": "ERROR_DS_CROSS_REF_EXISTS",
        "message": "A cross-reference already exists.",
    },
    0x000020B7: {
        "code": "ERROR_DS_CANT_DEL_MASTER_CROSSREF",
        "message": "It is not permitted to delete a master cross-reference.",
    },
    0x000020B8: {
        "code": "ERROR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD",
        "message": (
            "Subtree notifications are only supported on naming context (NC) heads."
        ),
    },
    0x000020B9: {
        "code": "ERROR_DS_NOTIFY_FILTER_TOO_COMPLEX",
        "message": "Notification filter is too complex.",
    },
    0x000020BA: {
        "code": "ERROR_DS_DUP_RDN",
        "message": "Schema update failed: Duplicate RDN.",
    },
    0x000020BB: {
        "code": "ERROR_DS_DUP_OID",
        "message": "Schema update failed: Duplicate OID.",
    },
    0x000020BC: {
        "code": "ERROR_DS_DUP_MAPI_ID",
        "message": (
            "Schema update failed: Duplicate Message Application Programming Interface"
            " (MAPI) identifier."
        ),
    },
    0x000020BD: {
        "code": "ERROR_DS_DUP_SCHEMA_ID_GUID",
        "message": "Schema update failed: Duplicate schema ID GUID.",
    },
    0x000020BE: {
        "code": "ERROR_DS_DUP_LDAP_DISPLAY_NAME",
        "message": "Schema update failed: Duplicate LDAP display name.",
    },
    0x000020BF: {
        "code": "ERROR_DS_SEMANTIC_ATT_TEST",
        "message": "Schema update failed: Range-Lower less than Range-Upper.",
    },
    0x000020C0: {
        "code": "ERROR_DS_SYNTAX_MISMATCH",
        "message": "Schema update failed: Syntax mismatch.",
    },
    0x000020C1: {
        "code": "ERROR_DS_EXISTS_IN_MUST_HAVE",
        "message": (
            "Schema deletion failed: Attribute is used in the Must-Contain list."
        ),
    },
    0x000020C2: {
        "code": "ERROR_DS_EXISTS_IN_MAY_HAVE",
        "message": "Schema deletion failed: Attribute is used in the May-Contain list.",
    },
    0x000020C3: {
        "code": "ERROR_DS_NONEXISTENT_MAY_HAVE",
        "message": (
            "Schema update failed: Attribute in May-Contain list does not exist."
        ),
    },
    0x000020C4: {
        "code": "ERROR_DS_NONEXISTENT_MUST_HAVE",
        "message": (
            "Schema update failed: Attribute in the Must-Contain list does not exist."
        ),
    },
    0x000020C5: {
        "code": "ERROR_DS_AUX_CLS_TEST_FAIL",
        "message": (
            "Schema update failed: Class in the Aux Class list does not exist or is not"
            " an auxiliary class."
        ),
    },
    0x000020C6: {
        "code": "ERROR_DS_NONEXISTENT_POSS_SUP",
        "message": (
            "Schema update failed: Class in the Poss-Superiors list does not exist."
        ),
    },
    0x000020C7: {
        "code": "ERROR_DS_SUB_CLS_TEST_FAIL",
        "message": (
            "Schema update failed: Class in the subclass of the list does not exist or"
            " does not satisfy hierarchy rules."
        ),
    },
    0x000020C8: {
        "code": "ERROR_DS_BAD_RDN_ATT_ID_SYNTAX",
        "message": "Schema update failed: Rdn-Att-Id has wrong syntax.",
    },
    0x000020C9: {
        "code": "ERROR_DS_EXISTS_IN_AUX_CLS",
        "message": "Schema deletion failed: Class is used as an auxiliary class.",
    },
    0x000020CA: {
        "code": "ERROR_DS_EXISTS_IN_SUB_CLS",
        "message": "Schema deletion failed: Class is used as a subclass.",
    },
    0x000020CB: {
        "code": "ERROR_DS_EXISTS_IN_POSS_SUP",
        "message": "Schema deletion failed: Class is used as a Poss-Superior.",
    },
    0x000020CC: {
        "code": "ERROR_DS_RECALCSCHEMA_FAILED",
        "message": "Schema update failed in recalculating validation cache.",
    },
    0x000020CD: {
        "code": "ERROR_DS_TREE_DELETE_NOT_FINISHED",
        "message": (
            "The tree deletion is not finished. The request must be made again to"
            " continue deleting the tree."
        ),
    },
    0x000020CE: {
        "code": "ERROR_DS_CANT_DELETE",
        "message": "The requested delete operation could not be performed.",
    },
    0x000020CF: {
        "code": "ERROR_DS_ATT_SCHEMA_REQ_ID",
        "message": "Cannot read the governs class identifier for the schema record.",
    },
    0x000020D0: {
        "code": "ERROR_DS_BAD_ATT_SCHEMA_SYNTAX",
        "message": "The attribute schema has bad syntax.",
    },
    0x000020D1: {
        "code": "ERROR_DS_CANT_CACHE_ATT",
        "message": "The attribute could not be cached.",
    },
    0x000020D2: {
        "code": "ERROR_DS_CANT_CACHE_CLASS",
        "message": "The class could not be cached.",
    },
    0x000020D3: {
        "code": "ERROR_DS_CANT_REMOVE_ATT_CACHE",
        "message": "The attribute could not be removed from the cache.",
    },
    0x000020D4: {
        "code": "ERROR_DS_CANT_REMOVE_CLASS_CACHE",
        "message": "The class could not be removed from the cache.",
    },
    0x000020D5: {
        "code": "ERROR_DS_CANT_RETRIEVE_DN",
        "message": "The distinguished name attribute could not be read.",
    },
    0x000020D6: {
        "code": "ERROR_DS_MISSING_SUPREF",
        "message": (
            "No superior reference has been configured for the directory service. The"
            " directory service is, therefore, unable to issue referrals to objects"
            " outside this forest."
        ),
    },
    0x000020D7: {
        "code": "ERROR_DS_CANT_RETRIEVE_INSTANCE",
        "message": "The instance type attribute could not be retrieved.",
    },
    0x000020D8: {
        "code": "ERROR_DS_CODE_INCONSISTENCY",
        "message": "An internal error has occurred.",
    },
    0x000020D9: {
        "code": "ERROR_DS_DATABASE_ERROR",
        "message": "A database error has occurred.",
    },
    0x000020DA: {
        "code": "ERROR_DS_GOVERNSID_MISSING",
        "message": "The governsID attribute is missing.",
    },
    0x000020DB: {
        "code": "ERROR_DS_MISSING_EXPECTED_ATT",
        "message": "An expected attribute is missing.",
    },
    0x000020DC: {
        "code": "ERROR_DS_NCNAME_MISSING_CR_REF",
        "message": "The specified naming context is missing a cross-reference.",
    },
    0x000020DD: {
        "code": "ERROR_DS_SECURITY_CHECKING_ERROR",
        "message": "A security checking error has occurred.",
    },
    0x000020DE: {
        "code": "ERROR_DS_SCHEMA_NOT_LOADED",
        "message": "The schema is not loaded.",
    },
    0x000020DF: {
        "code": "ERROR_DS_SCHEMA_ALLOC_FAILED",
        "message": (
            "Schema allocation failed. Check if the machine is running low on memory."
        ),
    },
    0x000020E0: {
        "code": "ERROR_DS_ATT_SCHEMA_REQ_SYNTAX",
        "message": "Failed to obtain the required syntax for the attribute schema.",
    },
    0x000020E1: {
        "code": "ERROR_DS_GCVERIFY_ERROR",
        "message": (
            "The GC verification failed. The GC is not available or does not support"
            " the operation. Some part of the directory is currently not available."
        ),
    },
    0x000020E2: {
        "code": "ERROR_DS_DRA_SCHEMA_MISMATCH",
        "message": (
            "The replication operation failed because of a schema mismatch between the"
            " servers involved."
        ),
    },
    0x000020E3: {
        "code": "ERROR_DS_CANT_FIND_DSA_OBJ",
        "message": "The DSA object could not be found.",
    },
    0x000020E4: {
        "code": "ERROR_DS_CANT_FIND_EXPECTED_NC",
        "message": "The naming context could not be found.",
    },
    0x000020E5: {
        "code": "ERROR_DS_CANT_FIND_NC_IN_CACHE",
        "message": "The naming context could not be found in the cache.",
    },
    0x000020E6: {
        "code": "ERROR_DS_CANT_RETRIEVE_CHILD",
        "message": "The child object could not be retrieved.",
    },
    0x000020E7: {
        "code": "ERROR_DS_SECURITY_ILLEGAL_MODIFY",
        "message": "The modification was not permitted for security reasons.",
    },
    0x000020E8: {
        "code": "ERROR_DS_CANT_REPLACE_HIDDEN_REC",
        "message": "The operation cannot replace the hidden record.",
    },
    0x000020E9: {
        "code": "ERROR_DS_BAD_HIERARCHY_FILE",
        "message": "The hierarchy file is invalid.",
    },
    0x000020EA: {
        "code": "ERROR_DS_BUILD_HIERARCHY_TABLE_FAILED",
        "message": "The attempt to build the hierarchy table failed.",
    },
    0x000020EB: {
        "code": "ERROR_DS_CONFIG_PARAM_MISSING",
        "message": (
            "The directory configuration parameter is missing from the registry."
        ),
    },
    0x000020EC: {
        "code": "ERROR_DS_COUNTING_AB_INDICES_FAILED",
        "message": "The attempt to count the address book indices failed.",
    },
    0x000020ED: {
        "code": "ERROR_DS_HIERARCHY_TABLE_MALLOC_FAILED",
        "message": "The allocation of the hierarchy table failed.",
    },
    0x000020EE: {
        "code": "ERROR_DS_INTERNAL_FAILURE",
        "message": "The directory service encountered an internal failure.",
    },
    0x000020EF: {
        "code": "ERROR_DS_UNKNOWN_ERROR",
        "message": "The directory service encountered an unknown failure.",
    },
    0x000020F0: {
        "code": "ERROR_DS_ROOT_REQUIRES_CLASS_TOP",
        "message": 'A root object requires a class of "top".',
    },
    0x000020F1: {
        "code": "ERROR_DS_REFUSING_FSMO_ROLES",
        "message": (
            "This directory server is shutting down, and cannot take ownership of new"
            " floating single-master operation roles."
        ),
    },
    0x000020F2: {
        "code": "ERROR_DS_MISSING_FSMO_SETTINGS",
        "message": (
            "The directory service is missing mandatory configuration information and"
            " is unable to determine the ownership of floating single-master operation"
            " roles."
        ),
    },
    0x000020F3: {
        "code": "ERROR_DS_UNABLE_TO_SURRENDER_ROLES",
        "message": (
            "The directory service was unable to transfer ownership of one or more"
            " floating single-master operation roles to other servers."
        ),
    },
    0x000020F4: {
        "code": "ERROR_DS_DRA_GENERIC",
        "message": "The replication operation failed.",
    },
    0x000020F5: {
        "code": "ERROR_DS_DRA_INVALID_PARAMETER",
        "message": "An invalid parameter was specified for this replication operation.",
    },
    0x000020F6: {
        "code": "ERROR_DS_DRA_BUSY",
        "message": (
            "The directory service is too busy to complete the replication operation at"
            " this time."
        ),
    },
    0x000020F7: {
        "code": "ERROR_DS_DRA_BAD_DN",
        "message": "The DN specified for this replication operation is invalid.",
    },
    0x000020F8: {
        "code": "ERROR_DS_DRA_BAD_NC",
        "message": (
            "The naming context specified for this replication operation is invalid."
        ),
    },
    0x000020F9: {
        "code": "ERROR_DS_DRA_DN_EXISTS",
        "message": "The DN specified for this replication operation already exists.",
    },
    0x000020FA: {
        "code": "ERROR_DS_DRA_INTERNAL_ERROR",
        "message": "The replication system encountered an internal error.",
    },
    0x000020FB: {
        "code": "ERROR_DS_DRA_INCONSISTENT_DIT",
        "message": "The replication operation encountered a database inconsistency.",
    },
    0x000020FC: {
        "code": "ERROR_DS_DRA_CONNECTION_FAILED",
        "message": (
            "The server specified for this replication operation could not be"
            " contacted."
        ),
    },
    0x000020FD: {
        "code": "ERROR_DS_DRA_BAD_INSTANCE_TYPE",
        "message": (
            "The replication operation encountered an object with an invalid instance"
            " type."
        ),
    },
    0x000020FE: {
        "code": "ERROR_DS_DRA_OUT_OF_MEM",
        "message": "The replication operation failed to allocate memory.",
    },
    0x000020FF: {
        "code": "ERROR_DS_DRA_MAIL_PROBLEM",
        "message": (
            "The replication operation encountered an error with the mail system."
        ),
    },
    0x00002100: {
        "code": "ERROR_DS_DRA_REF_ALREADY_EXISTS",
        "message": (
            "The replication reference information for the target server already"
            " exists."
        ),
    },
    0x00002101: {
        "code": "ERROR_DS_DRA_REF_NOT_FOUND",
        "message": (
            "The replication reference information for the target server does not"
            " exist."
        ),
    },
    0x00002102: {
        "code": "ERROR_DS_DRA_OBJ_IS_REP_SOURCE",
        "message": (
            "The naming context cannot be removed because it is replicated to another"
            " server."
        ),
    },
    0x00002103: {
        "code": "ERROR_DS_DRA_DB_ERROR",
        "message": "The replication operation encountered a database error.",
    },
    0x00002104: {
        "code": "ERROR_DS_DRA_NO_REPLICA",
        "message": (
            "The naming context is in the process of being removed or is not replicated"
            " from the specified server."
        ),
    },
    0x00002105: {
        "code": "ERROR_DS_DRA_ACCESS_DENIED",
        "message": "Replication access was denied.",
    },
    0x00002106: {
        "code": "ERROR_DS_DRA_NOT_SUPPORTED",
        "message": (
            "The requested operation is not supported by this version of the directory"
            " service."
        ),
    },
    0x00002107: {
        "code": "ERROR_DS_DRA_RPC_CANCELLED",
        "message": "The replication RPC was canceled.",
    },
    0x00002108: {
        "code": "ERROR_DS_DRA_SOURCE_DISABLED",
        "message": "The source server is currently rejecting replication requests.",
    },
    0x00002109: {
        "code": "ERROR_DS_DRA_SINK_DISABLED",
        "message": (
            "The destination server is currently rejecting replication requests."
        ),
    },
    0x0000210A: {
        "code": "ERROR_DS_DRA_NAME_COLLISION",
        "message": (
            "The replication operation failed due to a collision of object names."
        ),
    },
    0x0000210B: {
        "code": "ERROR_DS_DRA_SOURCE_REINSTALLED",
        "message": "The replication source has been reinstalled.",
    },
    0x0000210C: {
        "code": "ERROR_DS_DRA_MISSING_PARENT",
        "message": (
            "The replication operation failed because a required parent object is"
            " missing."
        ),
    },
    0x0000210D: {
        "code": "ERROR_DS_DRA_PREEMPTED",
        "message": "The replication operation was preempted.",
    },
    0x0000210E: {
        "code": "ERROR_DS_DRA_ABANDON_SYNC",
        "message": (
            "The replication synchronization attempt was abandoned because of a lack of"
            " updates."
        ),
    },
    0x0000210F: {
        "code": "ERROR_DS_DRA_SHUTDOWN",
        "message": (
            "The replication operation was terminated because the system is shutting"
            " down."
        ),
    },
    0x00002110: {
        "code": "ERROR_DS_DRA_INCOMPATIBLE_PARTIAL_SET",
        "message": (
            "A synchronization attempt failed because the destination DC is currently"
            " waiting to synchronize new partial attributes from the source. This"
            " condition is normal if a recent schema change modified the partial"
            " attribute set. The destination partial attribute set is not a subset of"
            " the source partial attribute set."
        ),
    },
    0x00002111: {
        "code": "ERROR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA",
        "message": (
            "The replication synchronization attempt failed because a master replica"
            " attempted to sync from a partial replica."
        ),
    },
    0x00002112: {
        "code": "ERROR_DS_DRA_EXTN_CONNECTION_FAILED",
        "message": (
            "The server specified for this replication operation was contacted, but"
            " that server was unable to contact an additional server needed to complete"
            " the operation."
        ),
    },
    0x00002113: {
        "code": "ERROR_DS_INSTALL_SCHEMA_MISMATCH",
        "message": (
            "The version of the directory service schema of the source forest is not"
            " compatible with the version of the directory service on this computer."
        ),
    },
    0x00002114: {
        "code": "ERROR_DS_DUP_LINK_ID",
        "message": (
            "Schema update failed: An attribute with the same link identifier already"
            " exists."
        ),
    },
    0x00002115: {
        "code": "ERROR_DS_NAME_ERROR_RESOLVING",
        "message": "Name translation: Generic processing error.",
    },
    0x00002116: {
        "code": "ERROR_DS_NAME_ERROR_NOT_FOUND",
        "message": (
            "Name translation: Could not find the name or insufficient right to see"
            " name."
        ),
    },
    0x00002117: {
        "code": "ERROR_DS_NAME_ERROR_NOT_UNIQUE",
        "message": "Name translation: Input name mapped to more than one output name.",
    },
    0x00002118: {
        "code": "ERROR_DS_NAME_ERROR_NO_MAPPING",
        "message": (
            "Name translation: The input name was found but not the associated output"
            " format."
        ),
    },
    0x00002119: {
        "code": "ERROR_DS_NAME_ERROR_DOMAIN_ONLY",
        "message": (
            "Name translation: Unable to resolve completely, only the domain was found."
        ),
    },
    0x0000211A: {
        "code": "ERROR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING",
        "message": (
            "Name translation: Unable to perform purely syntactical mapping at the"
            " client without going out to the wire."
        ),
    },
    0x0000211B: {
        "code": "ERROR_DS_CONSTRUCTED_ATT_MOD",
        "message": "Modification of a constructed attribute is not allowed.",
    },
    0x0000211C: {
        "code": "ERROR_DS_WRONG_OM_OBJ_CLASS",
        "message": (
            "The OM-Object-Class specified is incorrect for an attribute with the"
            " specified syntax."
        ),
    },
    0x0000211D: {
        "code": "ERROR_DS_DRA_REPL_PENDING",
        "message": "The replication request has been posted; waiting for a reply.",
    },
    0x0000211E: {
        "code": "ERROR_DS_DS_REQUIRED",
        "message": (
            "The requested operation requires a directory service, and none was"
            " available."
        ),
    },
    0x0000211F: {
        "code": "ERROR_DS_INVALID_LDAP_DISPLAY_NAME",
        "message": (
            "The LDAP display name of the class or attribute contains non-ASCII"
            " characters."
        ),
    },
    0x00002120: {
        "code": "ERROR_DS_NON_BASE_SEARCH",
        "message": (
            "The requested search operation is only supported for base searches."
        ),
    },
    0x00002121: {
        "code": "ERROR_DS_CANT_RETRIEVE_ATTS",
        "message": "The search failed to retrieve attributes from the database.",
    },
    0x00002122: {
        "code": "ERROR_DS_BACKLINK_WITHOUT_LINK",
        "message": (
            "The schema update operation tried to add a backward link attribute that"
            " has no corresponding forward link."
        ),
    },
    0x00002123: {
        "code": "ERROR_DS_EPOCH_MISMATCH",
        "message": (
            "The source and destination of a cross-domain move do not agree on the"
            " object's epoch number. Either the source or the destination does not have"
            " the latest version of the object."
        ),
    },
    0x00002124: {
        "code": "ERROR_DS_SRC_NAME_MISMATCH",
        "message": (
            "The source and destination of a cross-domain move do not agree on the"
            " object's current name. Either the source or the destination does not have"
            " the latest version of the object."
        ),
    },
    0x00002125: {
        "code": "ERROR_DS_SRC_AND_DST_NC_IDENTICAL",
        "message": (
            "The source and destination for the cross-domain move operation are"
            " identical. The caller should use a local move operation instead of a"
            " cross-domain move operation."
        ),
    },
    0x00002126: {
        "code": "ERROR_DS_DST_NC_MISMATCH",
        "message": (
            "The source and destination for a cross-domain move do not agree on the"
            " naming contexts in the forest. Either the source or the destination does"
            " not have the latest version of the Partitions container."
        ),
    },
    0x00002127: {
        "code": "ERROR_DS_NOT_AUTHORITIVE_FOR_DST_NC",
        "message": (
            "The destination of a cross-domain move is not authoritative for the"
            " destination naming context."
        ),
    },
    0x00002128: {
        "code": "ERROR_DS_SRC_GUID_MISMATCH",
        "message": (
            "The source and destination of a cross-domain move do not agree on the"
            " identity of the source object. Either the source or the destination does"
            " not have the latest version of the source object."
        ),
    },
    0x00002129: {
        "code": "ERROR_DS_CANT_MOVE_DELETED_OBJECT",
        "message": (
            "The object being moved across domains is already known to be deleted by"
            " the destination server. The source server does not have the latest"
            " version of the source object."
        ),
    },
    0x0000212A: {
        "code": "ERROR_DS_PDC_OPERATION_IN_PROGRESS",
        "message": (
            "Another operation that requires exclusive access to the PDC FSMO is"
            " already in progress."
        ),
    },
    0x0000212B: {
        "code": "ERROR_DS_CROSS_DOMAIN_CLEANUP_REQD",
        "message": (
            "A cross-domain move operation failed because two versions of the moved"
            " object exist—one each in the source and destination domains. The"
            " destination object needs to be removed to restore the system to a"
            " consistent state."
        ),
    },
    0x0000212C: {
        "code": "ERROR_DS_ILLEGAL_XDOM_MOVE_OPERATION",
        "message": (
            "This object cannot be moved across domain boundaries either because"
            " cross-domain moves for this class are not allowed, or the object has some"
            " special characteristics, for example, a trust account or a restricted"
            " relative identifier (RID), that prevent its move."
        ),
    },
    0x0000212D: {
        "code": "ERROR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS",
        "message": (
            "Cannot move objects with memberships across domain boundaries because,"
            " once moved, this violates the membership conditions of the account group."
            " Remove the object from any account group memberships and retry."
        ),
    },
    0x0000212E: {
        "code": "ERROR_DS_NC_MUST_HAVE_NC_PARENT",
        "message": (
            "A naming context head must be the immediate child of another naming"
            " context head, not of an interior node."
        ),
    },
    0x0000212F: {
        "code": "ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE",
        "message": (
            "The directory cannot validate the proposed naming context name because it"
            " does not hold a replica of the naming context above the proposed naming"
            " context. Ensure that the domain naming master role is held by a server"
            " that is configured as a GC server, and that the server is up-to-date with"
            " its replication partners. (Applies only to Windows 2000 operating system"
            " domain naming masters.)"
        ),
    },
    0x00002130: {
        "code": "ERROR_DS_DST_DOMAIN_NOT_NATIVE",
        "message": "Destination domain must be in native mode.",
    },
    0x00002131: {
        "code": "ERROR_DS_MISSING_INFRASTRUCTURE_CONTAINER",
        "message": (
            "The operation cannot be performed because the server does not have an"
            " infrastructure container in the domain of interest."
        ),
    },
    0x00002132: {
        "code": "ERROR_DS_CANT_MOVE_ACCOUNT_GROUP",
        "message": "Cross-domain moves of nonempty account groups is not allowed.",
    },
    0x00002133: {
        "code": "ERROR_DS_CANT_MOVE_RESOURCE_GROUP",
        "message": "Cross-domain moves of nonempty resource groups is not allowed.",
    },
    0x00002134: {
        "code": "ERROR_DS_INVALID_SEARCH_FLAG",
        "message": (
            "The search flags for the attribute are invalid. The ambiguous name"
            " resolution (ANR) bit is valid only on attributes of Unicode or Teletex"
            " strings."
        ),
    },
    0x00002135: {
        "code": "ERROR_DS_NO_TREE_DELETE_ABOVE_NC",
        "message": (
            "Tree deletions starting at an object that has an NC head as a descendant"
            " are not allowed."
        ),
    },
    0x00002136: {
        "code": "ERROR_DS_COULDNT_LOCK_TREE_FOR_DELETE",
        "message": (
            "The directory service failed to lock a tree in preparation for a tree"
            " deletion because the tree was in use."
        ),
    },
    0x00002137: {
        "code": "ERROR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE",
        "message": (
            "The directory service failed to identify the list of objects to delete"
            " while attempting a tree deletion."
        ),
    },
    0x00002138: {
        "code": "ERROR_DS_SAM_INIT_FAILURE",
        "message": (
            "SAM initialization failed because of the following error: %1. Error"
            " Status: 0x%2. Click OK to shut down the system and reboot into Directory"
            " Services Restore Mode. Check the event log for detailed information."
        ),
    },
    0x00002139: {
        "code": "ERROR_DS_SENSITIVE_GROUP_VIOLATION",
        "message": (
            "Only an administrator can modify the membership list of an administrative"
            " group."
        ),
    },
    0x0000213A: {
        "code": "ERROR_DS_CANT_MOD_PRIMARYGROUPID",
        "message": "Cannot change the primary group ID of a domain controller account.",
    },
    0x0000213B: {
        "code": "ERROR_DS_ILLEGAL_BASE_SCHEMA_MOD",
        "message": "An attempt was made to modify the base schema.",
    },
    0x0000213C: {
        "code": "ERROR_DS_NONSAFE_SCHEMA_CHANGE",
        "message": (
            "Adding a new mandatory attribute to an existing class, deleting a"
            " mandatory attribute from an existing class, or adding an optional"
            " attribute to the special class Top that is not a backlink attribute"
            " (directly or through inheritance, for example, by adding or deleting an"
            " auxiliary class) is not allowed."
        ),
    },
    0x0000213D: {
        "code": "ERROR_DS_SCHEMA_UPDATE_DISALLOWED",
        "message": (
            "Schema update is not allowed on this DC because the DC is not the schema"
            " FSMO role owner."
        ),
    },
    0x0000213E: {
        "code": "ERROR_DS_CANT_CREATE_UNDER_SCHEMA",
        "message": (
            "An object of this class cannot be created under the schema container. You"
            " can only create Attribute-Schema and Class-Schema objects under the"
            " schema container."
        ),
    },
    0x0000213F: {
        "code": "ERROR_DS_INSTALL_NO_SRC_SCH_VERSION",
        "message": (
            "The replica or child install failed to get the objectVersion attribute on"
            " the schema container on the source DC. Either the attribute is missing on"
            " the schema container or the credentials supplied do not have permission"
            " to read it."
        ),
    },
    0x00002140: {
        "code": "ERROR_DS_INSTALL_NO_SCH_VERSION_IN_INIFILE",
        "message": (
            "The replica or child install failed to read the objectVersion attribute in"
            " the SCHEMA section of the file schema.ini in the System32 directory."
        ),
    },
    0x00002141: {
        "code": "ERROR_DS_INVALID_GROUP_TYPE",
        "message": "The specified group type is invalid.",
    },
    0x00002142: {
        "code": "ERROR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN",
        "message": (
            "You cannot nest global groups in a mixed domain if the group is"
            " security-enabled."
        ),
    },
    0x00002143: {
        "code": "ERROR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN",
        "message": (
            "You cannot nest local groups in a mixed domain if the group is"
            " security-enabled."
        ),
    },
    0x00002144: {
        "code": "ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER",
        "message": "A global group cannot have a local group as a member.",
    },
    0x00002145: {
        "code": "ERROR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER",
        "message": "A global group cannot have a universal group as a member.",
    },
    0x00002146: {
        "code": "ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER",
        "message": "A universal group cannot have a local group as a member.",
    },
    0x00002147: {
        "code": "ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER",
        "message": "A global group cannot have a cross-domain member.",
    },
    0x00002148: {
        "code": "ERROR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER",
        "message": (
            "A local group cannot have another cross domain local group as a member."
        ),
    },
    0x00002149: {
        "code": "ERROR_DS_HAVE_PRIMARY_MEMBERS",
        "message": (
            "A group with primary members cannot change to a security-disabled group."
        ),
    },
    0x0000214A: {
        "code": "ERROR_DS_STRING_SD_CONVERSION_FAILED",
        "message": (
            "The schema cache load failed to convert the string default security"
            " descriptor (SD) on a class-schema object."
        ),
    },
    0x0000214B: {
        "code": "ERROR_DS_NAMING_MASTER_GC",
        "message": (
            "Only DSAs configured to be GC servers should be allowed to hold the domain"
            " naming master FSMO role. (Applies only to Windows 2000 servers.)"
        ),
    },
    0x0000214C: {
        "code": "ERROR_DS_DNS_LOOKUP_FAILURE",
        "message": (
            "The DSA operation is unable to proceed because of a DNS lookup failure."
        ),
    },
    0x0000214D: {
        "code": "ERROR_DS_COULDNT_UPDATE_SPNS",
        "message": (
            "While processing a change to the DNS host name for an object, the SPN"
            " values could not be kept in sync."
        ),
    },
    0x0000214E: {
        "code": "ERROR_DS_CANT_RETRIEVE_SD",
        "message": "The Security Descriptor attribute could not be read.",
    },
    0x0000214F: {
        "code": "ERROR_DS_KEY_NOT_UNIQUE",
        "message": (
            "The object requested was not found, but an object with that key was found."
        ),
    },
    0x00002150: {
        "code": "ERROR_DS_WRONG_LINKED_ATT_SYNTAX",
        "message": (
            "The syntax of the linked attribute being added is incorrect. Forward links"
            " can only have syntax 2.5.5.1, 2.5.5.7, and 2.5.5.14, and backlinks can"
            " only have syntax 2.5.5.1."
        ),
    },
    0x00002151: {
        "code": "ERROR_DS_SAM_NEED_BOOTKEY_PASSWORD",
        "message": "SAM needs to get the boot password.",
    },
    0x00002152: {
        "code": "ERROR_DS_SAM_NEED_BOOTKEY_FLOPPY",
        "message": "SAM needs to get the boot key from the floppy disk.",
    },
    0x00002153: {
        "code": "ERROR_DS_CANT_START",
        "message": "Directory Service cannot start.",
    },
    0x00002154: {
        "code": "ERROR_DS_INIT_FAILURE",
        "message": "Directory Services could not start.",
    },
    0x00002155: {
        "code": "ERROR_DS_NO_PKT_PRIVACY_ON_CONNECTION",
        "message": (
            "The connection between client and server requires packet privacy or"
            " better."
        ),
    },
    0x00002156: {
        "code": "ERROR_DS_SOURCE_DOMAIN_IN_FOREST",
        "message": "The source domain cannot be in the same forest as the destination.",
    },
    0x00002157: {
        "code": "ERROR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST",
        "message": "The destination domain MUST be in the forest.",
    },
    0x00002158: {
        "code": "ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED",
        "message": (
            "The operation requires that destination domain auditing be enabled."
        ),
    },
    0x00002159: {
        "code": "ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN",
        "message": "The operation could not locate a DC for the source domain.",
    },
    0x0000215A: {
        "code": "ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER",
        "message": "The source object must be a group or user.",
    },
    0x0000215B: {
        "code": "ERROR_DS_SRC_SID_EXISTS_IN_FOREST",
        "message": "The source object's SID already exists in the destination forest.",
    },
    0x0000215C: {
        "code": "ERROR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH",
        "message": "The source and destination object must be of the same type.",
    },
    0x0000215D: {
        "code": "ERROR_SAM_INIT_FAILURE",
        "message": (
            "SAM initialization failed because of the following error: %1. Error"
            " Status: 0x%2. Click OK to shut down the system and reboot into Safe Mode."
            " Check the event log for detailed information."
        ),
    },
    0x0000215E: {
        "code": "ERROR_DS_DRA_SCHEMA_INFO_SHIP",
        "message": (
            "Schema information could not be included in the replication request."
        ),
    },
    0x0000215F: {
        "code": "ERROR_DS_DRA_SCHEMA_CONFLICT",
        "message": (
            "The replication operation could not be completed due to a schema"
            " incompatibility."
        ),
    },
    0x00002160: {
        "code": "ERROR_DS_DRA_EARLIER_SCHEMA_CONFLICT",
        "message": (
            "The replication operation could not be completed due to a previous schema"
            " incompatibility."
        ),
    },
    0x00002161: {
        "code": "ERROR_DS_DRA_OBJ_NC_MISMATCH",
        "message": (
            "The replication update could not be applied because either the source or"
            " the destination has not yet received information regarding a recent"
            " cross-domain move operation."
        ),
    },
    0x00002162: {
        "code": "ERROR_DS_NC_STILL_HAS_DSAS",
        "message": (
            "The requested domain could not be deleted because there exist domain"
            " controllers that still host this domain."
        ),
    },
    0x00002163: {
        "code": "ERROR_DS_GC_REQUIRED",
        "message": "The requested operation can be performed only on a GC server.",
    },
    0x00002164: {
        "code": "ERROR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY",
        "message": (
            "A local group can only be a member of other local groups in the same"
            " domain."
        ),
    },
    0x00002165: {
        "code": "ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS",
        "message": "Foreign security principals cannot be members of universal groups.",
    },
    0x00002166: {
        "code": "ERROR_DS_CANT_ADD_TO_GC",
        "message": (
            "The attribute is not allowed to be replicated to the GC because of"
            " security reasons."
        ),
    },
    0x00002167: {
        "code": "ERROR_DS_NO_CHECKPOINT_WITH_PDC",
        "message": (
            "The checkpoint with the PDC could not be taken because too many"
            " modifications are currently being processed."
        ),
    },
    0x00002168: {
        "code": "ERROR_DS_SOURCE_AUDITING_NOT_ENABLED",
        "message": "The operation requires that source domain auditing be enabled.",
    },
    0x00002169: {
        "code": "ERROR_DS_CANT_CREATE_IN_NONDOMAIN_NC",
        "message": (
            "Security principal objects can only be created inside domain naming"
            " contexts."
        ),
    },
    0x0000216A: {
        "code": "ERROR_DS_INVALID_NAME_FOR_SPN",
        "message": (
            "An SPN could not be constructed because the provided host name is not in"
            " the necessary format."
        ),
    },
    0x0000216B: {
        "code": "ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS",
        "message": "A filter was passed that uses constructed attributes.",
    },
    0x0000216C: {
        "code": "ERROR_DS_UNICODEPWD_NOT_IN_QUOTES",
        "message": (
            "The unicodePwd attribute value must be enclosed in quotation marks."
        ),
    },
    0x0000216D: {
        "code": "ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED",
        "message": (
            "Your computer could not be joined to the domain. You have exceeded the"
            " maximum number of computer accounts you are allowed to create in this"
            " domain. Contact your system administrator to have this limit reset or"
            " increased."
        ),
    },
    0x0000216E: {
        "code": "ERROR_DS_MUST_BE_RUN_ON_DST_DC",
        "message": (
            "For security reasons, the operation must be run on the destination DC."
        ),
    },
    0x0000216F: {
        "code": "ERROR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER",
        "message": "For security reasons, the source DC must be NT4SP4 or greater.",
    },
    0x00002170: {
        "code": "ERROR_DS_CANT_TREE_DELETE_CRITICAL_OBJ",
        "message": (
            "Critical directory service system objects cannot be deleted during tree"
            " deletion operations. The tree deletion might have been partially"
            " performed."
        ),
    },
    0x00002171: {
        "code": "ERROR_DS_INIT_FAILURE_CONSOLE",
        "message": (
            "Directory Services could not start because of the following error: %1."
            " Error Status: 0x%2. Click OK to shut down the system. You can use the"
            " Recovery Console to further diagnose the system."
        ),
    },
    0x00002172: {
        "code": "ERROR_DS_SAM_INIT_FAILURE_CONSOLE",
        "message": (
            "SAM initialization failed because of the following error: %1. Error"
            " Status: 0x%2. Click OK to shut down the system. You can use the Recovery"
            " Console to further diagnose the system."
        ),
    },
    0x00002173: {
        "code": "ERROR_DS_FOREST_VERSION_TOO_HIGH",
        "message": (
            "The version of the operating system installed is incompatible with the"
            " current forest functional level. You must upgrade to a new version of the"
            " operating system before this server can become a domain controller in"
            " this forest."
        ),
    },
    0x00002174: {
        "code": "ERROR_DS_DOMAIN_VERSION_TOO_HIGH",
        "message": (
            "The version of the operating system installed is incompatible with the"
            " current domain functional level. You must upgrade to a new version of the"
            " operating system before this server can become a domain controller in"
            " this domain."
        ),
    },
    0x00002175: {
        "code": "ERROR_DS_FOREST_VERSION_TOO_LOW",
        "message": (
            "The version of the operating system installed on this server no longer"
            " supports the current forest functional level. You must raise the forest"
            " functional level before this server can become a domain controller in"
            " this forest."
        ),
    },
    0x00002176: {
        "code": "ERROR_DS_DOMAIN_VERSION_TOO_LOW",
        "message": (
            "The version of the operating system installed on this server no longer"
            " supports the current domain functional level. You must raise the domain"
            " functional level before this server can become a domain controller in"
            " this domain."
        ),
    },
    0x00002177: {
        "code": "ERROR_DS_INCOMPATIBLE_VERSION",
        "message": (
            "The version of the operating system installed on this server is"
            " incompatible with the functional level of the domain or forest."
        ),
    },
    0x00002178: {
        "code": "ERROR_DS_LOW_DSA_VERSION",
        "message": (
            "The functional level of the domain (or forest) cannot be raised to the"
            " requested value because one or more domain controllers in the domain (or"
            " forest) are at a lower, incompatible functional level."
        ),
    },
    0x00002179: {
        "code": "ERROR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN",
        "message": (
            "The forest functional level cannot be raised to the requested value"
            " because one or more domains are still in mixed-domain mode. All domains"
            " in the forest must be in native mode for you to raise the forest"
            " functional level."
        ),
    },
    0x0000217A: {
        "code": "ERROR_DS_NOT_SUPPORTED_SORT_ORDER",
        "message": "The sort order requested is not supported.",
    },
    0x0000217B: {
        "code": "ERROR_DS_NAME_NOT_UNIQUE",
        "message": "The requested name already exists as a unique identifier.",
    },
    0x0000217C: {
        "code": "ERROR_DS_MACHINE_ACCOUNT_CREATED_PRENT4",
        "message": (
            "The machine account was created before Windows NT 4.0. The account needs"
            " to be re-created."
        ),
    },
    0x0000217D: {
        "code": "ERROR_DS_OUT_OF_VERSION_STORE",
        "message": "The database is out of version store.",
    },
    0x0000217E: {
        "code": "ERROR_DS_INCOMPATIBLE_CONTROLS_USED",
        "message": (
            "Unable to continue operation because multiple conflicting controls were"
            " used."
        ),
    },
    0x0000217F: {
        "code": "ERROR_DS_NO_REF_DOMAIN",
        "message": (
            "Unable to find a valid security descriptor reference domain for this"
            " partition."
        ),
    },
    0x00002180: {
        "code": "ERROR_DS_RESERVED_LINK_ID",
        "message": "Schema update failed: The link identifier is reserved.",
    },
    0x00002181: {
        "code": "ERROR_DS_LINK_ID_NOT_AVAILABLE",
        "message": "Schema update failed: There are no link identifiers available.",
    },
    0x00002182: {
        "code": "ERROR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER",
        "message": "An account group cannot have a universal group as a member.",
    },
    0x00002183: {
        "code": "ERROR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE",
        "message": (
            "Rename or move operations on naming context heads or read-only objects are"
            " not allowed."
        ),
    },
    0x00002184: {
        "code": "ERROR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC",
        "message": (
            "Move operations on objects in the schema naming context are not allowed."
        ),
    },
    0x00002185: {
        "code": "ERROR_DS_MODIFYDN_DISALLOWED_BY_FLAG",
        "message": (
            "A system flag has been set on the object that does not allow the object to"
            " be moved or renamed."
        ),
    },
    0x00002186: {
        "code": "ERROR_DS_MODIFYDN_WRONG_GRANDPARENT",
        "message": (
            "This object is not allowed to change its grandparent container. Moves are"
            " not forbidden on this object, but are restricted to sibling containers."
        ),
    },
    0x00002187: {
        "code": "ERROR_DS_NAME_ERROR_TRUST_REFERRAL",
        "message": (
            "Unable to resolve completely; a referral to another forest was generated."
        ),
    },
    0x00002188: {
        "code": "ERROR_NOT_SUPPORTED_ON_STANDARD_SERVER",
        "message": "The requested action is not supported on a standard server.",
    },
    0x00002189: {
        "code": "ERROR_DS_CANT_ACCESS_REMOTE_PART_OF_AD",
        "message": (
            "Could not access a partition of the directory service located on a remote"
            " server. Make sure at least one server is running for the partition in"
            " question."
        ),
    },
    0x0000218A: {
        "code": "ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2",
        "message": (
            "The directory cannot validate the proposed naming context (or partition)"
            " name because it does not hold a replica, nor can it contact a replica of"
            " the naming context above the proposed naming context. Ensure that the"
            " parent naming context is properly registered in the DNS, and at least one"
            " replica of this naming context is reachable by the domain naming master."
        ),
    },
    0x0000218B: {
        "code": "ERROR_DS_THREAD_LIMIT_EXCEEDED",
        "message": "The thread limit for this request was exceeded.",
    },
    0x0000218C: {
        "code": "ERROR_DS_NOT_CLOSEST",
        "message": "The GC server is not in the closest site.",
    },
    0x0000218D: {
        "code": "ERROR_DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF",
        "message": (
            "The directory service cannot derive an SPN with which to mutually"
            " authenticate the target server because the corresponding server object in"
            " the local DS database has no serverReference attribute."
        ),
    },
    0x0000218E: {
        "code": "ERROR_DS_SINGLE_USER_MODE_FAILED",
        "message": "The directory service failed to enter single-user mode.",
    },
    0x0000218F: {
        "code": "ERROR_DS_NTDSCRIPT_SYNTAX_ERROR",
        "message": (
            "The directory service cannot parse the script because of a syntax error."
        ),
    },
    0x00002190: {
        "code": "ERROR_DS_NTDSCRIPT_PROCESS_ERROR",
        "message": (
            "The directory service cannot process the script because of an error."
        ),
    },
    0x00002191: {
        "code": "ERROR_DS_DIFFERENT_REPL_EPOCHS",
        "message": (
            "The directory service cannot perform the requested operation because the"
            " servers involved are of different replication epochs (which is usually"
            " related to a domain rename that is in progress)."
        ),
    },
    0x00002192: {
        "code": "ERROR_DS_DRS_EXTENSIONS_CHANGED",
        "message": (
            "The directory service binding must be renegotiated due to a change in the"
            " server extensions information."
        ),
    },
    0x00002193: {
        "code": "ERROR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR",
        "message": "The operation is not allowed on a disabled cross-reference.",
    },
    0x00002194: {
        "code": "ERROR_DS_NO_MSDS_INTID",
        "message": "Schema update failed: No values for msDS-IntId are available.",
    },
    0x00002195: {
        "code": "ERROR_DS_DUP_MSDS_INTID",
        "message": "Schema update failed: Duplicate msDS-IntId. Retry the operation.",
    },
    0x00002196: {
        "code": "ERROR_DS_EXISTS_IN_RDNATTID",
        "message": "Schema deletion failed: Attribute is used in rDNAttID.",
    },
    0x00002197: {
        "code": "ERROR_DS_AUTHORIZATION_FAILED",
        "message": "The directory service failed to authorize the request.",
    },
    0x00002198: {
        "code": "ERROR_DS_INVALID_SCRIPT",
        "message": (
            "The directory service cannot process the script because it is invalid."
        ),
    },
    0x00002199: {
        "code": "ERROR_DS_REMOTE_CROSSREF_OP_FAILED",
        "message": (
            "The remote create cross-reference operation failed on the domain naming"
            " master FSMO. The operation's error is in the extended data."
        ),
    },
    0x0000219A: {
        "code": "ERROR_DS_CROSS_REF_BUSY",
        "message": "A cross-reference is in use locally with the same name.",
    },
    0x0000219B: {
        "code": "ERROR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN",
        "message": (
            "The directory service cannot derive an SPN with which to mutually"
            " authenticate the target server because the server's domain has been"
            " deleted from the forest."
        ),
    },
    0x0000219C: {
        "code": "ERROR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC",
        "message": "Writable NCs prevent this DC from demoting.",
    },
    0x0000219D: {
        "code": "ERROR_DS_DUPLICATE_ID_FOUND",
        "message": (
            "The requested object has a nonunique identifier and cannot be retrieved."
        ),
    },
    0x0000219E: {
        "code": "ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT",
        "message": (
            "Insufficient attributes were given to create an object. This object might"
            " not exist because it might have been deleted and the garbage already"
            " collected."
        ),
    },
    0x0000219F: {
        "code": "ERROR_DS_GROUP_CONVERSION_ERROR",
        "message": (
            "The group cannot be converted due to attribute restrictions on the"
            " requested group type."
        ),
    },
    0x000021A0: {
        "code": "ERROR_DS_CANT_MOVE_APP_BASIC_GROUP",
        "message": (
            "Cross-domain moves of nonempty basic application groups is not allowed."
        ),
    },
    0x000021A1: {
        "code": "ERROR_DS_CANT_MOVE_APP_QUERY_GROUP",
        "message": (
            "Cross-domain moves of nonempty query-based application groups is not"
            " allowed."
        ),
    },
    0x000021A2: {
        "code": "ERROR_DS_ROLE_NOT_VERIFIED",
        "message": (
            "The FSMO role ownership could not be verified because its directory"
            " partition did not replicate successfully with at least one replication"
            " partner."
        ),
    },
    0x000021A3: {
        "code": "ERROR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL",
        "message": (
            "The target container for a redirection of a well-known object container"
            " cannot already be a special container."
        ),
    },
    0x000021A4: {
        "code": "ERROR_DS_DOMAIN_RENAME_IN_PROGRESS",
        "message": (
            "The directory service cannot perform the requested operation because a"
            " domain rename operation is in progress."
        ),
    },
    0x000021A5: {
        "code": "ERROR_DS_EXISTING_AD_CHILD_NC",
        "message": (
            "The directory service detected a child partition below the requested"
            " partition name. The partition hierarchy must be created in a top down"
            " method."
        ),
    },
    0x000021A6: {
        "code": "ERROR_DS_REPL_LIFETIME_EXCEEDED",
        "message": (
            "The directory service cannot replicate with this server because the time"
            " since the last replication with this server has exceeded the tombstone"
            " lifetime."
        ),
    },
    0x000021A7: {
        "code": "ERROR_DS_DISALLOWED_IN_SYSTEM_CONTAINER",
        "message": (
            "The requested operation is not allowed on an object under the system"
            " container."
        ),
    },
    0x000021A8: {
        "code": "ERROR_DS_LDAP_SEND_QUEUE_FULL",
        "message": (
            "The LDAP server's network send queue has filled up because the client is"
            " not processing the results of its requests fast enough. No more requests"
            " will be processed until the client catches up. If the client does not"
            " catch up then it will be disconnected."
        ),
    },
    0x000021A9: {
        "code": "ERROR_DS_DRA_OUT_SCHEDULE_WINDOW",
        "message": (
            "The scheduled replication did not take place because the system was too"
            " busy to execute the request within the schedule window. The replication"
            " queue is overloaded. Consider reducing the number of partners or"
            " decreasing the scheduled replication frequency."
        ),
    },
    0x000021AA: {
        "code": "ERROR_DS_POLICY_NOT_KNOWN",
        "message": (
            "At this time, it cannot be determined if the branch replication policy is"
            " available on the hub domain controller. Retry at a later time to account"
            " for replication latencies."
        ),
    },
    0x000021AB: {
        "code": "ERROR_NO_SITE_SETTINGS_OBJECT",
        "message": "The site settings object for the specified site does not exist.",
    },
    0x000021AC: {
        "code": "ERROR_NO_SECRETS",
        "message": (
            "The local account store does not contain secret material for the specified"
            " account."
        ),
    },
    0x000021AD: {
        "code": "ERROR_NO_WRITABLE_DC_FOUND",
        "message": "Could not find a writable domain controller in the domain.",
    },
    0x000021AE: {
        "code": "ERROR_DS_NO_SERVER_OBJECT",
        "message": "The server object for the domain controller does not exist.",
    },
    0x000021AF: {
        "code": "ERROR_DS_NO_NTDSA_OBJECT",
        "message": "The NTDS Settings object for the domain controller does not exist.",
    },
    0x000021B0: {
        "code": "ERROR_DS_NON_ASQ_SEARCH",
        "message": (
            "The requested search operation is not supported for attribute scoped query"
            " (ASQ) searches."
        ),
    },
    0x000021B1: {
        "code": "ERROR_DS_AUDIT_FAILURE",
        "message": "A required audit event could not be generated for the operation.",
    },
    0x000021B2: {
        "code": "ERROR_DS_INVALID_SEARCH_FLAG_SUBTREE",
        "message": (
            "The search flags for the attribute are invalid. The subtree index bit is"
            " valid only on single-valued attributes."
        ),
    },
    0x000021B3: {
        "code": "ERROR_DS_INVALID_SEARCH_FLAG_TUPLE",
        "message": (
            "The search flags for the attribute are invalid. The tuple index bit is"
            " valid only on attributes of Unicode strings."
        ),
    },
    0x000021BF: {
        "code": "ERROR_DS_DRA_RECYCLED_TARGET",
        "message": (
            "The replication operation failed because the target object referenced by a"
            " link value is recycled."
        ),
    },
    0x000021C2: {
        "code": "ERROR_DS_HIGH_DSA_VERSION",
        "message": (
            "The functional level of the domain (or forest) cannot be lowered to the"
            " requested value."
        ),
    },
    0x000021C7: {
        "code": "ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST",
        "message": (
            "The operation failed because the SPN value provided for"
            " addition/modification is not unique forest-wide."
        ),
    },
    0x000021C8: {
        "code": "ERROR_DS_UPN_VALUE_NOT_UNIQUE_IN_FOREST",
        "message": (
            "The operation failed because the UPN value provided for"
            " addition/modification is not unique forest-wide."
        ),
    },
    0x00002329: {
        "code": "DNS_ERROR_RCODE_FORMAT_ERROR",
        "message": "DNS server unable to interpret format.",
    },
    0x0000232A: {
        "code": "DNS_ERROR_RCODE_SERVER_FAILURE",
        "message": "DNS server failure.",
    },
    0x0000232B: {
        "code": "DNS_ERROR_RCODE_NAME_ERROR",
        "message": "DNS name does not exist.",
    },
    0x0000232C: {
        "code": "DNS_ERROR_RCODE_NOT_IMPLEMENTED",
        "message": "DNS request not supported by name server.",
    },
    0x0000232D: {
        "code": "DNS_ERROR_RCODE_REFUSED",
        "message": "DNS operation refused.",
    },
    0x0000232E: {
        "code": "DNS_ERROR_RCODE_YXDOMAIN",
        "message": "DNS name that should not exist, does exist.",
    },
    0x0000232F: {
        "code": "DNS_ERROR_RCODE_YXRRSET",
        "message": "DNS resource record (RR) set that should not exist, does exist.",
    },
    0x00002330: {
        "code": "DNS_ERROR_RCODE_NXRRSET",
        "message": "DNS RR set that should to exist, does not exist.",
    },
    0x00002331: {
        "code": "DNS_ERROR_RCODE_NOTAUTH",
        "message": "DNS server not authoritative for zone.",
    },
    0x00002332: {
        "code": "DNS_ERROR_RCODE_NOTZONE",
        "message": "DNS name in update or prereq is not in zone.",
    },
    0x00002338: {
        "code": "DNS_ERROR_RCODE_BADSIG",
        "message": "DNS signature failed to verify.",
    },
    0x00002339: {"code": "DNS_ERROR_RCODE_BADKEY", "message": "DNS bad key."},
    0x0000233A: {
        "code": "DNS_ERROR_RCODE_BADTIME",
        "message": "DNS signature validity expired.",
    },
    0x0000251D: {
        "code": "DNS_INFO_NO_RECORDS",
        "message": "No records found for given DNS query.",
    },
    0x0000251E: {"code": "DNS_ERROR_BAD_PACKET", "message": "Bad DNS packet."},
    0x0000251F: {"code": "DNS_ERROR_NO_PACKET", "message": "No DNS packet."},
    0x00002520: {"code": "DNS_ERROR_RCODE", "message": "DNS error, check rcode."},
    0x00002521: {
        "code": "DNS_ERROR_UNSECURE_PACKET",
        "message": "Unsecured DNS packet.",
    },
    0x0000254F: {"code": "DNS_ERROR_INVALID_TYPE", "message": "Invalid DNS type."},
    0x00002550: {
        "code": "DNS_ERROR_INVALID_IP_ADDRESS",
        "message": "Invalid IP address.",
    },
    0x00002551: {"code": "DNS_ERROR_INVALID_PROPERTY", "message": "Invalid property."},
    0x00002552: {
        "code": "DNS_ERROR_TRY_AGAIN_LATER",
        "message": "Try DNS operation again later.",
    },
    0x00002553: {
        "code": "DNS_ERROR_NOT_UNIQUE",
        "message": "Record for given name and type is not unique.",
    },
    0x00002554: {
        "code": "DNS_ERROR_NON_RFC_NAME",
        "message": "DNS name does not comply with RFC specifications.",
    },
    0x00002555: {
        "code": "DNS_STATUS_FQDN",
        "message": "DNS name is a fully qualified DNS name.",
    },
    0x00002556: {
        "code": "DNS_STATUS_DOTTED_NAME",
        "message": "DNS name is dotted (multilabel).",
    },
    0x00002557: {
        "code": "DNS_STATUS_SINGLE_PART_NAME",
        "message": "DNS name is a single-part name.",
    },
    0x00002558: {
        "code": "DNS_ERROR_INVALID_NAME_CHAR",
        "message": "DNS name contains an invalid character.",
    },
    0x00002559: {
        "code": "DNS_ERROR_NUMERIC_NAME",
        "message": "DNS name is entirely numeric.",
    },
    0x0000255A: {
        "code": "DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER",
        "message": "The operation requested is not permitted on a DNS root server.",
    },
    0x0000255B: {
        "code": "DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION",
        "message": (
            "The record could not be created because this part of the DNS namespace has"
            " been delegated to another server."
        ),
    },
    0x0000255C: {
        "code": "DNS_ERROR_CANNOT_FIND_ROOT_HINTS",
        "message": "The DNS server could not find a set of root hints.",
    },
    0x0000255D: {
        "code": "DNS_ERROR_INCONSISTENT_ROOT_HINTS",
        "message": (
            "The DNS server found root hints but they were not consistent across all"
            " adapters."
        ),
    },
    0x0000255E: {
        "code": "DNS_ERROR_DWORD_VALUE_TOO_SMALL",
        "message": "The specified value is too small for this parameter.",
    },
    0x0000255F: {
        "code": "DNS_ERROR_DWORD_VALUE_TOO_LARGE",
        "message": "The specified value is too large for this parameter.",
    },
    0x00002560: {
        "code": "DNS_ERROR_BACKGROUND_LOADING",
        "message": (
            "This operation is not allowed while the DNS server is loading zones in the"
            " background. Try again later."
        ),
    },
    0x00002561: {
        "code": "DNS_ERROR_NOT_ALLOWED_ON_RODC",
        "message": (
            "The operation requested is not permitted on against a DNS server running"
            " on a read-only DC."
        ),
    },
    0x00002581: {
        "code": "DNS_ERROR_ZONE_DOES_NOT_EXIST",
        "message": "DNS zone does not exist.",
    },
    0x00002582: {
        "code": "DNS_ERROR_NO_ZONE_INFO",
        "message": "DNS zone information not available.",
    },
    0x00002583: {
        "code": "DNS_ERROR_INVALID_ZONE_OPERATION",
        "message": "Invalid operation for DNS zone.",
    },
    0x00002584: {
        "code": "DNS_ERROR_ZONE_CONFIGURATION_ERROR",
        "message": "Invalid DNS zone configuration.",
    },
    0x00002585: {
        "code": "DNS_ERROR_ZONE_HAS_NO_SOA_RECORD",
        "message": "DNS zone has no start of authority (SOA) record.",
    },
    0x00002586: {
        "code": "DNS_ERROR_ZONE_HAS_NO_NS_RECORDS",
        "message": "DNS zone has no Name Server (NS) record.",
    },
    0x00002587: {"code": "DNS_ERROR_ZONE_LOCKED", "message": "DNS zone is locked."},
    0x00002588: {
        "code": "DNS_ERROR_ZONE_CREATION_FAILED",
        "message": "DNS zone creation failed.",
    },
    0x00002589: {
        "code": "DNS_ERROR_ZONE_ALREADY_EXISTS",
        "message": "DNS zone already exists.",
    },
    0x0000258A: {
        "code": "DNS_ERROR_AUTOZONE_ALREADY_EXISTS",
        "message": "DNS automatic zone already exists.",
    },
    0x0000258B: {
        "code": "DNS_ERROR_INVALID_ZONE_TYPE",
        "message": "Invalid DNS zone type.",
    },
    0x0000258C: {
        "code": "DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP",
        "message": "Secondary DNS zone requires master IP address.",
    },
    0x0000258D: {
        "code": "DNS_ERROR_ZONE_NOT_SECONDARY",
        "message": "DNS zone not secondary.",
    },
    0x0000258E: {
        "code": "DNS_ERROR_NEED_SECONDARY_ADDRESSES",
        "message": "Need secondary IP address.",
    },
    0x0000258F: {
        "code": "DNS_ERROR_WINS_INIT_FAILED",
        "message": "WINS initialization failed.",
    },
    0x00002590: {
        "code": "DNS_ERROR_NEED_WINS_SERVERS",
        "message": "Need WINS servers.",
    },
    0x00002591: {
        "code": "DNS_ERROR_NBSTAT_INIT_FAILED",
        "message": "NBTSTAT initialization call failed.",
    },
    0x00002592: {
        "code": "DNS_ERROR_SOA_DELETE_INVALID",
        "message": "Invalid delete of SOA.",
    },
    0x00002593: {
        "code": "DNS_ERROR_FORWARDER_ALREADY_EXISTS",
        "message": "A conditional forwarding zone already exists for that name.",
    },
    0x00002594: {
        "code": "DNS_ERROR_ZONE_REQUIRES_MASTER_IP",
        "message": (
            "This zone must be configured with one or more master DNS server IP"
            " addresses."
        ),
    },
    0x00002595: {
        "code": "DNS_ERROR_ZONE_IS_SHUTDOWN",
        "message": "The operation cannot be performed because this zone is shut down.",
    },
    0x000025B3: {
        "code": "DNS_ERROR_PRIMARY_REQUIRES_DATAFILE",
        "message": "The primary DNS zone requires a data file.",
    },
    0x000025B4: {
        "code": "DNS_ERROR_INVALID_DATAFILE_NAME",
        "message": "Invalid data file name for the DNS zone.",
    },
    0x000025B5: {
        "code": "DNS_ERROR_DATAFILE_OPEN_FAILURE",
        "message": "Failed to open the data file for the DNS zone.",
    },
    0x000025B6: {
        "code": "DNS_ERROR_FILE_WRITEBACK_FAILED",
        "message": "Failed to write the data file for the DNS zone.",
    },
    0x000025B7: {
        "code": "DNS_ERROR_DATAFILE_PARSING",
        "message": "Failure while reading datafile for DNS zone.",
    },
    0x000025E5: {
        "code": "DNS_ERROR_RECORD_DOES_NOT_EXIST",
        "message": "DNS record does not exist.",
    },
    0x000025E6: {
        "code": "DNS_ERROR_RECORD_FORMAT",
        "message": "DNS record format error.",
    },
    0x000025E7: {
        "code": "DNS_ERROR_NODE_CREATION_FAILED",
        "message": "Node creation failure in DNS.",
    },
    0x000025E8: {
        "code": "DNS_ERROR_UNKNOWN_RECORD_TYPE",
        "message": "Unknown DNS record type.",
    },
    0x000025E9: {
        "code": "DNS_ERROR_RECORD_TIMED_OUT",
        "message": "DNS record timed out.",
    },
    0x000025EA: {
        "code": "DNS_ERROR_NAME_NOT_IN_ZONE",
        "message": "Name not in DNS zone.",
    },
    0x000025EB: {"code": "DNS_ERROR_CNAME_LOOP", "message": "CNAME loop detected."},
    0x000025EC: {
        "code": "DNS_ERROR_NODE_IS_CNAME",
        "message": "Node is a CNAME DNS record.",
    },
    0x000025ED: {
        "code": "DNS_ERROR_CNAME_COLLISION",
        "message": "A CNAME record already exists for the given name.",
    },
    0x000025EE: {
        "code": "DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT",
        "message": "Record is only at DNS zone root.",
    },
    0x000025EF: {
        "code": "DNS_ERROR_RECORD_ALREADY_EXISTS",
        "message": "DNS record already exists.",
    },
    0x000025F0: {
        "code": "DNS_ERROR_SECONDARY_DATA",
        "message": "Secondary DNS zone data error.",
    },
    0x000025F1: {
        "code": "DNS_ERROR_NO_CREATE_CACHE_DATA",
        "message": "Could not create DNS cache data.",
    },
    0x000025F2: {
        "code": "DNS_ERROR_NAME_DOES_NOT_EXIST",
        "message": "DNS name does not exist.",
    },
    0x000025F3: {
        "code": "DNS_WARNING_PTR_CREATE_FAILED",
        "message": "Could not create pointer (PTR) record.",
    },
    0x000025F4: {
        "code": "DNS_WARNING_DOMAIN_UNDELETED",
        "message": "DNS domain was undeleted.",
    },
    0x000025F5: {
        "code": "DNS_ERROR_DS_UNAVAILABLE",
        "message": "The directory service is unavailable.",
    },
    0x000025F6: {
        "code": "DNS_ERROR_DS_ZONE_ALREADY_EXISTS",
        "message": "DNS zone already exists in the directory service.",
    },
    0x000025F7: {
        "code": "DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE",
        "message": (
            "DNS server not creating or reading the boot file for the directory service"
            " integrated DNS zone."
        ),
    },
    0x00002617: {
        "code": "DNS_INFO_AXFR_COMPLETE",
        "message": "DNS AXFR (zone transfer) complete.",
    },
    0x00002618: {"code": "DNS_ERROR_AXFR", "message": "DNS zone transfer failed."},
    0x00002619: {
        "code": "DNS_INFO_ADDED_LOCAL_WINS",
        "message": "Added local WINS server.",
    },
    0x00002649: {
        "code": "DNS_STATUS_CONTINUE_NEEDED",
        "message": "Secure update call needs to continue update request.",
    },
    0x0000267B: {
        "code": "DNS_ERROR_NO_TCPIP",
        "message": "TCP/IP network protocol not installed.",
    },
    0x0000267C: {
        "code": "DNS_ERROR_NO_DNS_SERVERS",
        "message": "No DNS servers configured for local system.",
    },
    0x000026AD: {
        "code": "DNS_ERROR_DP_DOES_NOT_EXIST",
        "message": "The specified directory partition does not exist.",
    },
    0x000026AE: {
        "code": "DNS_ERROR_DP_ALREADY_EXISTS",
        "message": "The specified directory partition already exists.",
    },
    0x000026AF: {
        "code": "DNS_ERROR_DP_NOT_ENLISTED",
        "message": (
            "This DNS server is not enlisted in the specified directory partition."
        ),
    },
    0x000026B0: {
        "code": "DNS_ERROR_DP_ALREADY_ENLISTED",
        "message": (
            "This DNS server is already enlisted in the specified directory partition."
        ),
    },
    0x000026B1: {
        "code": "DNS_ERROR_DP_NOT_AVAILABLE",
        "message": (
            "The directory partition is not available at this time. Wait a few minutes"
            " and try again."
        ),
    },
    0x000026B2: {
        "code": "DNS_ERROR_DP_FSMO_ERROR",
        "message": (
            "The application directory partition operation failed. The domain"
            " controller holding the domain naming master role is down or unable to"
            " service the request or is not running Windows Server 2003."
        ),
    },
    0x00002714: {
        "code": "WSAEINTR",
        "message": (
            "A blocking operation was interrupted by a call to WSACancelBlockingCall."
        ),
    },
    0x00002719: {
        "code": "WSAEBADF",
        "message": "The file handle supplied is not valid.",
    },
    0x0000271D: {
        "code": "WSAEACCES",
        "message": (
            "An attempt was made to access a socket in a way forbidden by its access"
            " permissions."
        ),
    },
    0x0000271E: {
        "code": "WSAEFAULT",
        "message": (
            "The system detected an invalid pointer address in attempting to use a"
            " pointer argument in a call."
        ),
    },
    0x00002726: {"code": "WSAEINVAL", "message": "An invalid argument was supplied."},
    0x00002728: {"code": "WSAEMFILE", "message": "Too many open sockets."},
    0x00002733: {
        "code": "WSAEWOULDBLOCK",
        "message": "A nonblocking socket operation could not be completed immediately.",
    },
    0x00002734: {
        "code": "WSAEINPROGRESS",
        "message": "A blocking operation is currently executing.",
    },
    0x00002735: {
        "code": "WSAEALREADY",
        "message": (
            "An operation was attempted on a nonblocking socket that already had an"
            " operation in progress."
        ),
    },
    0x00002736: {
        "code": "WSAENOTSOCK",
        "message": "An operation was attempted on something that is not a socket.",
    },
    0x00002737: {
        "code": "WSAEDESTADDRREQ",
        "message": "A required address was omitted from an operation on a socket.",
    },
    0x00002738: {
        "code": "WSAEMSGSIZE",
        "message": (
            "A message sent on a datagram socket was larger than the internal message"
            " buffer or some other network limit, or the buffer used to receive a"
            " datagram into was smaller than the datagram itself."
        ),
    },
    0x00002739: {
        "code": "WSAEPROTOTYPE",
        "message": (
            "A protocol was specified in the socket function call that does not support"
            " the semantics of the socket type requested."
        ),
    },
    0x0000273A: {
        "code": "WSAENOPROTOOPT",
        "message": (
            "An unknown, invalid, or unsupported option or level was specified in a"
            " getsockopt or setsockopt call."
        ),
    },
    0x0000273B: {
        "code": "WSAEPROTONOSUPPORT",
        "message": (
            "The requested protocol has not been configured into the system, or no"
            " implementation for it exists."
        ),
    },
    0x0000273C: {
        "code": "WSAESOCKTNOSUPPORT",
        "message": (
            "The support for the specified socket type does not exist in this address"
            " family."
        ),
    },
    0x0000273D: {
        "code": "WSAEOPNOTSUPP",
        "message": (
            "The attempted operation is not supported for the type of object"
            " referenced."
        ),
    },
    0x0000273E: {
        "code": "WSAEPFNOSUPPORT",
        "message": (
            "The protocol family has not been configured into the system or no"
            " implementation for it exists."
        ),
    },
    0x0000273F: {
        "code": "WSAEAFNOSUPPORT",
        "message": "An address incompatible with the requested protocol was used.",
    },
    0x00002740: {
        "code": "WSAEADDRINUSE",
        "message": (
            "Only one usage of each socket address (protocol/network address/port) is"
            " normally permitted."
        ),
    },
    0x00002741: {
        "code": "WSAEADDRNOTAVAIL",
        "message": "The requested address is not valid in its context.",
    },
    0x00002742: {
        "code": "WSAENETDOWN",
        "message": "A socket operation encountered a dead network.",
    },
    0x00002743: {
        "code": "WSAENETUNREACH",
        "message": "A socket operation was attempted to an unreachable network.",
    },
    0x00002744: {
        "code": "WSAENETRESET",
        "message": (
            "The connection has been broken due to keep-alive activity detecting a"
            " failure while the operation was in progress."
        ),
    },
    0x00002745: {
        "code": "WSAECONNABORTED",
        "message": (
            "An established connection was aborted by the software in your host"
            " machine."
        ),
    },
    0x00002746: {
        "code": "WSAECONNRESET",
        "message": "An existing connection was forcibly closed by the remote host.",
    },
    0x00002747: {
        "code": "WSAENOBUFS",
        "message": (
            "An operation on a socket could not be performed because the system lacked"
            " sufficient buffer space or because a queue was full."
        ),
    },
    0x00002748: {
        "code": "WSAEISCONN",
        "message": "A connect request was made on an already connected socket.",
    },
    0x00002749: {
        "code": "WSAENOTCONN",
        "message": (
            "A request to send or receive data was disallowed because the socket is not"
            " connected and (when sending on a datagram socket using a sendto call) no"
            " address was supplied."
        ),
    },
    0x0000274A: {
        "code": "WSAESHUTDOWN",
        "message": (
            "A request to send or receive data was disallowed because the socket had"
            " already been shut down in that direction with a previous shutdown call."
        ),
    },
    0x0000274B: {
        "code": "WSAETOOMANYREFS",
        "message": "Too many references to a kernel object.",
    },
    0x0000274C: {
        "code": "WSAETIMEDOUT",
        "message": (
            "A connection attempt failed because the connected party did not properly"
            " respond after a period of time, or the established connection failed"
            " because the connected host failed to respond."
        ),
    },
    0x0000274D: {
        "code": "WSAECONNREFUSED",
        "message": (
            "No connection could be made because the target machine actively"
            " refused it."
        ),
    },
    0x0000274E: {"code": "WSAELOOP", "message": "Cannot translate name."},
    0x0000274F: {
        "code": "WSAENAMETOOLONG",
        "message": "Name or name component was too long.",
    },
    0x00002750: {
        "code": "WSAEHOSTDOWN",
        "message": "A socket operation failed because the destination host was down.",
    },
    0x00002751: {
        "code": "WSAEHOSTUNREACH",
        "message": "A socket operation was attempted to an unreachable host.",
    },
    0x00002752: {
        "code": "WSAENOTEMPTY",
        "message": "Cannot remove a directory that is not empty.",
    },
    0x00002753: {
        "code": "WSAEPROCLIM",
        "message": (
            "A Windows Sockets implementation might have a limit on the number of"
            " applications that can use it simultaneously."
        ),
    },
    0x00002754: {"code": "WSAEUSERS", "message": "Ran out of quota."},
    0x00002755: {"code": "WSAEDQUOT", "message": "Ran out of disk quota."},
    0x00002756: {
        "code": "WSAESTALE",
        "message": "File handle reference is no longer available.",
    },
    0x00002757: {"code": "WSAEREMOTE", "message": "Item is not available locally."},
    0x0000276B: {
        "code": "WSASYSNOTREADY",
        "message": (
            "WSAStartup cannot function at this time because the underlying system it"
            " uses to provide network services is currently unavailable."
        ),
    },
    0x0000276C: {
        "code": "WSAVERNOTSUPPORTED",
        "message": "The Windows Sockets version requested is not supported.",
    },
    0x0000276D: {
        "code": "WSANOTINITIALISED",
        "message": (
            "Either the application has not called WSAStartup, or WSAStartup failed."
        ),
    },
    0x00002775: {
        "code": "WSAEDISCON",
        "message": (
            "Returned by WSARecv or WSARecvFrom to indicate that the remote party has"
            " initiated a graceful shutdown sequence."
        ),
    },
    0x00002776: {
        "code": "WSAENOMORE",
        "message": "No more results can be returned by WSALookupServiceNext.",
    },
    0x00002777: {
        "code": "WSAECANCELLED",
        "message": (
            "A call to WSALookupServiceEnd was made while this call was still"
            " processing. The call has been canceled."
        ),
    },
    0x00002778: {
        "code": "WSAEINVALIDPROCTABLE",
        "message": "The procedure call table is invalid.",
    },
    0x00002779: {
        "code": "WSAEINVALIDPROVIDER",
        "message": "The requested service provider is invalid.",
    },
    0x0000277A: {
        "code": "WSAEPROVIDERFAILEDINIT",
        "message": "The requested service provider could not be loaded or initialized.",
    },
    0x0000277B: {
        "code": "WSASYSCALLFAILURE",
        "message": "A system call that should never fail has failed.",
    },
    0x0000277C: {
        "code": "WSASERVICE_NOT_FOUND",
        "message": (
            "No such service is known. The service cannot be found in the specified"
            " namespace."
        ),
    },
    0x0000277D: {
        "code": "WSATYPE_NOT_FOUND",
        "message": "The specified class was not found.",
    },
    0x0000277E: {
        "code": "WSA_E_NO_MORE",
        "message": "No more results can be returned by WSALookupServiceNext.",
    },
    0x0000277F: {
        "code": "WSA_E_CANCELLED",
        "message": (
            "A call to WSALookupServiceEnd was made while this call was still"
            " processing. The call has been canceled."
        ),
    },
    0x00002780: {
        "code": "WSAEREFUSED",
        "message": "A database query failed because it was actively refused.",
    },
    0x00002AF9: {"code": "WSAHOST_NOT_FOUND", "message": "No such host is known."},
    0x00002AFA: {
        "code": "WSATRY_AGAIN",
        "message": (
            "This is usually a temporary error during host name resolution and means"
            " that the local server did not receive a response from an authoritative"
            " server."
        ),
    },
    0x00002AFB: {
        "code": "WSANO_RECOVERY",
        "message": "A nonrecoverable error occurred during a database lookup.",
    },
    0x00002AFC: {
        "code": "WSANO_DATA",
        "message": (
            "The requested name is valid, but no data of the requested type was found."
        ),
    },
    0x00002AFD: {
        "code": "WSA_QOS_RECEIVERS",
        "message": "At least one reserve has arrived.",
    },
    0x00002AFE: {
        "code": "WSA_QOS_SENDERS",
        "message": "At least one path has arrived.",
    },
    0x00002AFF: {"code": "WSA_QOS_NO_SENDERS", "message": "There are no senders."},
    0x00002B00: {"code": "WSA_QOS_NO_RECEIVERS", "message": "There are no receivers."},
    0x00002B01: {
        "code": "WSA_QOS_REQUEST_CONFIRMED",
        "message": "Reserve has been confirmed.",
    },
    0x00002B02: {
        "code": "WSA_QOS_ADMISSION_FAILURE",
        "message": "Error due to lack of resources.",
    },
    0x00002B03: {
        "code": "WSA_QOS_POLICY_FAILURE",
        "message": "Rejected for administrative reasons—bad credentials.",
    },
    0x00002B04: {
        "code": "WSA_QOS_BAD_STYLE",
        "message": "Unknown or conflicting style.",
    },
    0x00002B05: {
        "code": "WSA_QOS_BAD_OBJECT",
        "message": (
            "There is a problem with some part of the filterspec or provider-specific"
            " buffer in general."
        ),
    },
    0x00002B06: {
        "code": "WSA_QOS_TRAFFIC_CTRL_ERROR",
        "message": "There is a problem with some part of the flowspec.",
    },
    0x00002B07: {
        "code": "WSA_QOS_GENERIC_ERROR",
        "message": "General quality of serve (QOS) error.",
    },
    0x00002B08: {
        "code": "WSA_QOS_ESERVICETYPE",
        "message": "An invalid or unrecognized service type was found in the flowspec.",
    },
    0x00002B09: {
        "code": "WSA_QOS_EFLOWSPEC",
        "message": (
            "An invalid or inconsistent flowspec was found in the QOS structure."
        ),
    },
    0x00002B0A: {
        "code": "WSA_QOS_EPROVSPECBUF",
        "message": "Invalid QOS provider-specific buffer.",
    },
    0x00002B0B: {
        "code": "WSA_QOS_EFILTERSTYLE",
        "message": "An invalid QOS filter style was used.",
    },
    0x00002B0C: {
        "code": "WSA_QOS_EFILTERTYPE",
        "message": "An invalid QOS filter type was used.",
    },
    0x00002B0D: {
        "code": "WSA_QOS_EFILTERCOUNT",
        "message": (
            "An incorrect number of QOS FILTERSPECs were specified in the"
            " FLOWDESCRIPTOR."
        ),
    },
    0x00002B0E: {
        "code": "WSA_QOS_EOBJLENGTH",
        "message": (
            "An object with an invalid ObjectLength field was specified in the QOS"
            " provider-specific buffer."
        ),
    },
    0x00002B0F: {
        "code": "WSA_QOS_EFLOWCOUNT",
        "message": (
            "An incorrect number of flow descriptors was specified in the QOS"
            " structure."
        ),
    },
    0x00002B10: {
        "code": "WSA_QOS_EUNKOWNPSOBJ",
        "message": (
            "An unrecognized object was found in the QOS provider-specific buffer."
        ),
    },
    0x00002B11: {
        "code": "WSA_QOS_EPOLICYOBJ",
        "message": (
            "An invalid policy object was found in the QOS provider-specific buffer."
        ),
    },
    0x00002B12: {
        "code": "WSA_QOS_EFLOWDESC",
        "message": (
            "An invalid QOS flow descriptor was found in the flow descriptor list."
        ),
    },
    0x00002B13: {
        "code": "WSA_QOS_EPSFLOWSPEC",
        "message": (
            "An invalid or inconsistent flowspec was found in the QOS provider-specific"
            " buffer."
        ),
    },
    0x00002B14: {
        "code": "WSA_QOS_EPSFILTERSPEC",
        "message": (
            "An invalid FILTERSPEC was found in the QOS provider-specific buffer."
        ),
    },
    0x00002B15: {
        "code": "WSA_QOS_ESDMODEOBJ",
        "message": (
            "An invalid shape discard mode object was found in the QOS"
            " provider-specific buffer."
        ),
    },
    0x00002B16: {
        "code": "WSA_QOS_ESHAPERATEOBJ",
        "message": (
            "An invalid shaping rate object was found in the QOS provider-specific"
            " buffer."
        ),
    },
    0x00002B17: {
        "code": "WSA_QOS_RESERVED_PETYPE",
        "message": (
            "A reserved policy element was found in the QOS provider-specific buffer."
        ),
    },
    0x000032C8: {
        "code": "ERROR_IPSEC_QM_POLICY_EXISTS",
        "message": "The specified quick mode policy already exists.",
    },
    0x000032C9: {
        "code": "ERROR_IPSEC_QM_POLICY_NOT_FOUND",
        "message": "The specified quick mode policy was not found.",
    },
    0x000032CA: {
        "code": "ERROR_IPSEC_QM_POLICY_IN_USE",
        "message": "The specified quick mode policy is being used.",
    },
    0x000032CB: {
        "code": "ERROR_IPSEC_MM_POLICY_EXISTS",
        "message": "The specified main mode policy already exists.",
    },
    0x000032CC: {
        "code": "ERROR_IPSEC_MM_POLICY_NOT_FOUND",
        "message": "The specified main mode policy was not found.",
    },
    0x000032CD: {
        "code": "ERROR_IPSEC_MM_POLICY_IN_USE",
        "message": "The specified main mode policy is being used.",
    },
    0x000032CE: {
        "code": "ERROR_IPSEC_MM_FILTER_EXISTS",
        "message": "The specified main mode filter already exists.",
    },
    0x000032CF: {
        "code": "ERROR_IPSEC_MM_FILTER_NOT_FOUND",
        "message": "The specified main mode filter was not found.",
    },
    0x000032D0: {
        "code": "ERROR_IPSEC_TRANSPORT_FILTER_EXISTS",
        "message": "The specified transport mode filter already exists.",
    },
    0x000032D1: {
        "code": "ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND",
        "message": "The specified transport mode filter does not exist.",
    },
    0x000032D2: {
        "code": "ERROR_IPSEC_MM_AUTH_EXISTS",
        "message": "The specified main mode authentication list exists.",
    },
    0x000032D3: {
        "code": "ERROR_IPSEC_MM_AUTH_NOT_FOUND",
        "message": "The specified main mode authentication list was not found.",
    },
    0x000032D4: {
        "code": "ERROR_IPSEC_MM_AUTH_IN_USE",
        "message": "The specified main mode authentication list is being used.",
    },
    0x000032D5: {
        "code": "ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND",
        "message": "The specified default main mode policy was not found.",
    },
    0x000032D6: {
        "code": "ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND",
        "message": "The specified default main mode authentication list was not found.",
    },
    0x000032D7: {
        "code": "ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND",
        "message": "The specified default quick mode policy was not found.",
    },
    0x000032D8: {
        "code": "ERROR_IPSEC_TUNNEL_FILTER_EXISTS",
        "message": "The specified tunnel mode filter exists.",
    },
    0x000032D9: {
        "code": "ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND",
        "message": "The specified tunnel mode filter was not found.",
    },
    0x000032DA: {
        "code": "ERROR_IPSEC_MM_FILTER_PENDING_DELETION",
        "message": "The main mode filter is pending deletion.",
    },
    0x000032DB: {
        "code": "ERROR_IPSEC_TRANSPORT_FILTER_ENDING_DELETION",
        "message": "The transport filter is pending deletion.",
    },
    0x000032DC: {
        "code": "ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION",
        "message": "The tunnel filter is pending deletion.",
    },
    0x000032DD: {
        "code": "ERROR_IPSEC_MM_POLICY_PENDING_ELETION",
        "message": "The main mode policy is pending deletion.",
    },
    0x000032DE: {
        "code": "ERROR_IPSEC_MM_AUTH_PENDING_DELETION",
        "message": "The main mode authentication bundle is pending deletion.",
    },
    0x000032DF: {
        "code": "ERROR_IPSEC_QM_POLICY_PENDING_DELETION",
        "message": "The quick mode policy is pending deletion.",
    },
    0x000032E0: {
        "code": "WARNING_IPSEC_MM_POLICY_PRUNED",
        "message": (
            "The main mode policy was successfully added, but some of the requested"
            " offers are not supported."
        ),
    },
    0x000032E1: {
        "code": "WARNING_IPSEC_QM_POLICY_PRUNED",
        "message": (
            "The quick mode policy was successfully added, but some of the requested"
            " offers are not supported."
        ),
    },
    0x000035E8: {
        "code": "ERROR_IPSEC_IKE_NEG_STATUS_BEGIN",
        "message": (
            "Starts the list of frequencies of various IKE Win32 error codes"
            " encountered during negotiations."
        ),
    },
    0x000035E9: {
        "code": "ERROR_IPSEC_IKE_AUTH_FAIL",
        "message": "The IKE authentication credentials are unacceptable.",
    },
    0x000035EA: {
        "code": "ERROR_IPSEC_IKE_ATTRIB_FAIL",
        "message": "The IKE security attributes are unacceptable.",
    },
    0x000035EB: {
        "code": "ERROR_IPSEC_IKE_NEGOTIATION_PENDING",
        "message": "The IKE negotiation is in progress.",
    },
    0x000035EC: {
        "code": "ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR",
        "message": "General processing error.",
    },
    0x000035ED: {
        "code": "ERROR_IPSEC_IKE_TIMED_OUT",
        "message": "Negotiation timed out.",
    },
    0x000035EE: {
        "code": "ERROR_IPSEC_IKE_NO_CERT",
        "message": (
            "The IKE failed to find a valid machine certificate. Contact your network"
            " security administrator about installing a valid certificate in the"
            " appropriate certificate store."
        ),
    },
    0x000035EF: {
        "code": "ERROR_IPSEC_IKE_SA_DELETED",
        "message": (
            "The IKE security association (SA) was deleted by a peer before it was"
            " completely established."
        ),
    },
    0x000035F0: {
        "code": "ERROR_IPSEC_IKE_SA_REAPED",
        "message": "The IKE SA was deleted before it was completely established.",
    },
    0x000035F1: {
        "code": "ERROR_IPSEC_IKE_MM_ACQUIRE_DROP",
        "message": "The negotiation request sat in the queue too long.",
    },
    0x000035F2: {
        "code": "ERROR_IPSEC_IKE_QM_ACQUIRE_DROP",
        "message": "The negotiation request sat in the queue too long.",
    },
    0x000035F3: {
        "code": "ERROR_IPSEC_IKE_QUEUE_DROP_MM",
        "message": "The negotiation request sat in the queue too long.",
    },
    0x000035F4: {
        "code": "ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM",
        "message": "The negotiation request sat in the queue too long.",
    },
    0x000035F5: {
        "code": "ERROR_IPSEC_IKE_DROP_NO_RESPONSE",
        "message": "There was no response from a peer.",
    },
    0x000035F6: {
        "code": "ERROR_IPSEC_IKE_MM_DELAY_DROP",
        "message": "The negotiation took too long.",
    },
    0x000035F7: {
        "code": "ERROR_IPSEC_IKE_QM_DELAY_DROP",
        "message": "The negotiation took too long.",
    },
    0x000035F8: {
        "code": "ERROR_IPSEC_IKE_ERROR",
        "message": "An unknown error occurred.",
    },
    0x000035F9: {
        "code": "ERROR_IPSEC_IKE_CRL_FAILED",
        "message": "The certificate revocation check failed.",
    },
    0x000035FA: {
        "code": "ERROR_IPSEC_IKE_INVALID_KEY_USAGE",
        "message": "Invalid certificate key usage.",
    },
    0x000035FB: {
        "code": "ERROR_IPSEC_IKE_INVALID_CERT_TYPE",
        "message": "Invalid certificate type.",
    },
    0x000035FC: {
        "code": "ERROR_IPSEC_IKE_NO_PRIVATE_KEY",
        "message": (
            "The IKE negotiation failed because the machine certificate used does not"
            " have a private key. IPsec certificates require a private key. Contact"
            " your network security administrator about a certificate that has a"
            " private key."
        ),
    },
    0x000035FE: {
        "code": "ERROR_IPSEC_IKE_DH_FAIL",
        "message": "There was a failure in the Diffie-Hellman computation.",
    },
    0x00003600: {
        "code": "ERROR_IPSEC_IKE_INVALID_HEADER",
        "message": "Invalid header.",
    },
    0x00003601: {
        "code": "ERROR_IPSEC_IKE_NO_POLICY",
        "message": "No policy configured.",
    },
    0x00003602: {
        "code": "ERROR_IPSEC_IKE_INVALID_SIGNATURE",
        "message": "Failed to verify signature.",
    },
    0x00003603: {
        "code": "ERROR_IPSEC_IKE_KERBEROS_ERROR",
        "message": "Failed to authenticate using Kerberos.",
    },
    0x00003604: {
        "code": "ERROR_IPSEC_IKE_NO_PUBLIC_KEY",
        "message": "The peer's certificate did not have a public key.",
    },
    0x00003605: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR",
        "message": "Error processing the error payload.",
    },
    0x00003606: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_SA",
        "message": "Error processing the SA payload.",
    },
    0x00003607: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_PROP",
        "message": "Error processing the proposal payload.",
    },
    0x00003608: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_TRANS",
        "message": "Error processing the transform payload.",
    },
    0x00003609: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_KE",
        "message": "Error processing the key exchange payload.",
    },
    0x0000360A: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_ID",
        "message": "Error processing the ID payload.",
    },
    0x0000360B: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_CERT",
        "message": "Error processing the certification payload.",
    },
    0x0000360C: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ",
        "message": "Error processing the certificate request payload.",
    },
    0x0000360D: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_HASH",
        "message": "Error processing the hash payload.",
    },
    0x0000360E: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_SIG",
        "message": "Error processing the signature payload.",
    },
    0x0000360F: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_NONCE",
        "message": "Error processing the nonce payload.",
    },
    0x00003610: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY",
        "message": "Error processing the notify payload.",
    },
    0x00003611: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_DELETE",
        "message": "Error processing the delete payload.",
    },
    0x00003612: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR",
        "message": "Error processing the VendorId payload.",
    },
    0x00003613: {
        "code": "ERROR_IPSEC_IKE_INVALID_PAYLOAD",
        "message": "Invalid payload received.",
    },
    0x00003614: {"code": "ERROR_IPSEC_IKE_LOAD_SOFT_SA", "message": "Soft SA loaded."},
    0x00003615: {
        "code": "ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN",
        "message": "Soft SA torn down.",
    },
    0x00003616: {
        "code": "ERROR_IPSEC_IKE_INVALID_COOKIE",
        "message": "Invalid cookie received.",
    },
    0x00003617: {
        "code": "ERROR_IPSEC_IKE_NO_PEER_CERT",
        "message": "Peer failed to send valid machine certificate.",
    },
    0x00003618: {
        "code": "ERROR_IPSEC_IKE_PEER_CRL_FAILED",
        "message": "Certification revocation check of peer's certificate failed.",
    },
    0x00003619: {
        "code": "ERROR_IPSEC_IKE_POLICY_CHANGE",
        "message": "New policy invalidated SAs formed with the old policy.",
    },
    0x0000361A: {
        "code": "ERROR_IPSEC_IKE_NO_MM_POLICY",
        "message": "There is no available main mode IKE policy.",
    },
    0x0000361B: {
        "code": "ERROR_IPSEC_IKE_NOTCBPRIV",
        "message": "Failed to enabled trusted computer base (TCB) privilege.",
    },
    0x0000361C: {
        "code": "ERROR_IPSEC_IKE_SECLOADFAIL",
        "message": "Failed to load SECURITY.DLL.",
    },
    0x0000361D: {
        "code": "ERROR_IPSEC_IKE_FAILSSPINIT",
        "message": (
            "Failed to obtain the security function table dispatch address from the"
            " SSPI."
        ),
    },
    0x0000361E: {
        "code": "ERROR_IPSEC_IKE_FAILQUERYSSP",
        "message": "Failed to query the Kerberos package to obtain the max token size.",
    },
    0x0000361F: {
        "code": "ERROR_IPSEC_IKE_SRVACQFAIL",
        "message": (
            "Failed to obtain the Kerberos server credentials for the Internet Security"
            " Association and Key Management Protocol (ISAKMP)/ERROR_IPSEC_IKE service."
            " Kerberos authentication will not function. The most likely reason for"
            " this is lack of domain membership. This is normal if your computer is a"
            " member of a workgroup."
        ),
    },
    0x00003620: {
        "code": "ERROR_IPSEC_IKE_SRVQUERYCRED",
        "message": (
            "Failed to determine the SSPI principal name for ISAKMP/ERROR_IPSEC_IKE"
            " service (QueryCredentialsAttributes)."
        ),
    },
    0x00003621: {
        "code": "ERROR_IPSEC_IKE_GETSPIFAIL",
        "message": (
            "Failed to obtain a new service provider interface (SPI) for the inbound SA"
            " from the IPsec driver. The most common cause for this is that the driver"
            " does not have the correct filter. Check your policy to verify the"
            " filters."
        ),
    },
    0x00003622: {
        "code": "ERROR_IPSEC_IKE_INVALID_FILTER",
        "message": "Given filter is invalid.",
    },
    0x00003623: {
        "code": "ERROR_IPSEC_IKE_OUT_OF_MEMORY",
        "message": "Memory allocation failed.",
    },
    0x00003624: {
        "code": "ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED",
        "message": (
            "Failed to add an SA to the IPSec driver. The most common cause for this is"
            " if the IKE negotiation took too long to complete. If the problem"
            " persists, reduce the load on the faulting machine."
        ),
    },
    0x00003625: {
        "code": "ERROR_IPSEC_IKE_INVALID_POLICY",
        "message": "Invalid policy.",
    },
    0x00003626: {
        "code": "ERROR_IPSEC_IKE_UNKNOWN_DOI",
        "message": "Invalid digital object identifier (DOI).",
    },
    0x00003627: {
        "code": "ERROR_IPSEC_IKE_INVALID_SITUATION",
        "message": "Invalid situation.",
    },
    0x00003628: {
        "code": "ERROR_IPSEC_IKE_DH_FAILURE",
        "message": "Diffie-Hellman failure.",
    },
    0x00003629: {
        "code": "ERROR_IPSEC_IKE_INVALID_GROUP",
        "message": "Invalid Diffie-Hellman group.",
    },
    0x0000362A: {
        "code": "ERROR_IPSEC_IKE_ENCRYPT",
        "message": "Error encrypting payload.",
    },
    0x0000362B: {
        "code": "ERROR_IPSEC_IKE_DECRYPT",
        "message": "Error decrypting payload.",
    },
    0x0000362C: {
        "code": "ERROR_IPSEC_IKE_POLICY_MATCH",
        "message": "Policy match error.",
    },
    0x0000362D: {
        "code": "ERROR_IPSEC_IKE_UNSUPPORTED_ID",
        "message": "Unsupported ID.",
    },
    0x0000362E: {
        "code": "ERROR_IPSEC_IKE_INVALID_HASH",
        "message": "Hash verification failed.",
    },
    0x0000362F: {
        "code": "ERROR_IPSEC_IKE_INVALID_HASH_ALG",
        "message": "Invalid hash algorithm.",
    },
    0x00003630: {
        "code": "ERROR_IPSEC_IKE_INVALID_HASH_SIZE",
        "message": "Invalid hash size.",
    },
    0x00003631: {
        "code": "ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG",
        "message": "Invalid encryption algorithm.",
    },
    0x00003632: {
        "code": "ERROR_IPSEC_IKE_INVALID_AUTH_ALG",
        "message": "Invalid authentication algorithm.",
    },
    0x00003633: {
        "code": "ERROR_IPSEC_IKE_INVALID_SIG",
        "message": "Invalid certificate signature.",
    },
    0x00003634: {"code": "ERROR_IPSEC_IKE_LOAD_FAILED", "message": "Load failed."},
    0x00003635: {
        "code": "ERROR_IPSEC_IKE_RPC_DELETE",
        "message": "Deleted by using an RPC call.",
    },
    0x00003636: {
        "code": "ERROR_IPSEC_IKE_BENIGN_REINIT",
        "message": (
            "A temporary state was created to perform reinitialization. This is not a"
            " real failure."
        ),
    },
    0x00003637: {
        "code": "ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY",
        "message": (
            "The lifetime value received in the Responder Lifetime Notify is below the"
            " Windows 2000 configured minimum value. Fix the policy on the peer"
            " machine."
        ),
    },
    0x00003639: {
        "code": "ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN",
        "message": (
            "Key length in the certificate is too small for configured security"
            " requirements."
        ),
    },
    0x0000363A: {
        "code": "ERROR_IPSEC_IKE_MM_LIMIT",
        "message": "Maximum number of established MM SAs to peer exceeded.",
    },
    0x0000363B: {
        "code": "ERROR_IPSEC_IKE_NEGOTIATION_DISABLED",
        "message": "The IKE received a policy that disables negotiation.",
    },
    0x0000363C: {
        "code": "ERROR_IPSEC_IKE_QM_LIMIT",
        "message": (
            "Reached maximum quick mode limit for the main mode. New main mode will be"
            " started."
        ),
    },
    0x0000363D: {
        "code": "ERROR_IPSEC_IKE_MM_EXPIRED",
        "message": "Main mode SA lifetime expired or the peer sent a main mode delete.",
    },
    0x0000363E: {
        "code": "ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID",
        "message": (
            "Main mode SA assumed to be invalid because peer stopped responding."
        ),
    },
    0x0000363F: {
        "code": "ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH",
        "message": "Certificate does not chain to a trusted root in IPsec policy.",
    },
    0x00003640: {
        "code": "ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID",
        "message": "Received unexpected message ID.",
    },
    0x00003641: {
        "code": "ERROR_IPSEC_IKE_INVALID_UMATTS",
        "message": "Received invalid AuthIP user mode attributes.",
    },
    0x00003642: {
        "code": "ERROR_IPSEC_IKE_DOS_COOKIE_SENT",
        "message": "Sent DOS cookie notify to initiator.",
    },
    0x00003643: {
        "code": "ERROR_IPSEC_IKE_SHUTTING_DOWN",
        "message": "The IKE service is shutting down.",
    },
    0x00003644: {
        "code": "ERROR_IPSEC_IKE_CGA_AUTH_FAILED",
        "message": (
            "Could not verify the binding between the color graphics adapter (CGA)"
            " address and the certificate."
        ),
    },
    0x00003645: {
        "code": "ERROR_IPSEC_IKE_PROCESS_ERR_NATOA",
        "message": "Error processing the NatOA payload.",
    },
    0x00003646: {
        "code": "ERROR_IPSEC_IKE_INVALID_MM_FOR_QM",
        "message": "The parameters of the main mode are invalid for this quick mode.",
    },
    0x00003647: {
        "code": "ERROR_IPSEC_IKE_QM_EXPIRED",
        "message": "The quick mode SA was expired by the IPsec driver.",
    },
    0x00003648: {
        "code": "ERROR_IPSEC_IKE_TOO_MANY_FILTERS",
        "message": "Too many dynamically added IKEEXT filters were detected.",
    },
    0x00003649: {
        "code": "ERROR_IPSEC_IKE_NEG_STATUS_END",
        "message": (
            "Ends the list of frequencies of various IKE Win32 error codes encountered"
            " during negotiations."
        ),
    },
    0x000036B0: {
        "code": "ERROR_SXS_SECTION_NOT_FOUND",
        "message": "The requested section was not present in the activation context.",
    },
    0x000036B1: {
        "code": "ERROR_SXS_CANT_GEN_ACTCTX",
        "message": (
            "The application has failed to start because its side-by-side configuration"
            " is incorrect. See the application event log for more detail."
        ),
    },
    0x000036B2: {
        "code": "ERROR_SXS_INVALID_ACTCTXDATA_FORMAT",
        "message": "The application binding data format is invalid.",
    },
    0x000036B3: {
        "code": "ERROR_SXS_ASSEMBLY_NOT_FOUND",
        "message": "The referenced assembly is not installed on your system.",
    },
    0x000036B4: {
        "code": "ERROR_SXS_MANIFEST_FORMAT_ERROR",
        "message": (
            "The manifest file does not begin with the required tag and format"
            " information."
        ),
    },
    0x000036B5: {
        "code": "ERROR_SXS_MANIFEST_PARSE_ERROR",
        "message": "The manifest file contains one or more syntax errors.",
    },
    0x000036B6: {
        "code": "ERROR_SXS_ACTIVATION_CONTEXT_DISABLED",
        "message": (
            "The application attempted to activate a disabled activation context."
        ),
    },
    0x000036B7: {
        "code": "ERROR_SXS_KEY_NOT_FOUND",
        "message": (
            "The requested lookup key was not found in any active activation context."
        ),
    },
    0x000036B8: {
        "code": "ERROR_SXS_VERSION_CONFLICT",
        "message": (
            "A component version required by the application conflicts with another"
            " active component version."
        ),
    },
    0x000036B9: {
        "code": "ERROR_SXS_WRONG_SECTION_TYPE",
        "message": (
            "The type requested activation context section does not match the query API"
            " used."
        ),
    },
    0x000036BA: {
        "code": "ERROR_SXS_THREAD_QUERIES_DISABLED",
        "message": (
            "Lack of system resources has required isolated activation to be disabled"
            " for the current thread of execution."
        ),
    },
    0x000036BB: {
        "code": "ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET",
        "message": (
            "An attempt to set the process default activation context failed because"
            " the process default activation context was already set."
        ),
    },
    0x000036BC: {
        "code": "ERROR_SXS_UNKNOWN_ENCODING_GROUP",
        "message": "The encoding group identifier specified is not recognized.",
    },
    0x000036BD: {
        "code": "ERROR_SXS_UNKNOWN_ENCODING",
        "message": "The encoding requested is not recognized.",
    },
    0x000036BE: {
        "code": "ERROR_SXS_INVALID_XML_NAMESPACE_URI",
        "message": "The manifest contains a reference to an invalid URI.",
    },
    0x000036BF: {
        "code": "ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_OT_INSTALLED",
        "message": (
            "The application manifest contains a reference to a dependent assembly that"
            " is not installed."
        ),
    },
    0x000036C0: {
        "code": "ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED",
        "message": (
            "The manifest for an assembly used by the application has a reference to a"
            " dependent assembly that is not installed."
        ),
    },
    0x000036C1: {
        "code": "ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE",
        "message": (
            "The manifest contains an attribute for the assembly identity that is not"
            " valid."
        ),
    },
    0x000036C2: {
        "code": "ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE",
        "message": (
            "The manifest is missing the required default namespace specification on"
            " the assembly element."
        ),
    },
    0x000036C3: {
        "code": "ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE",
        "message": (
            "The manifest has a default namespace specified on the assembly element but"
            ' its value is not urn:schemas-microsoft-com:asm.v1"."'
        ),
    },
    0x000036C4: {
        "code": "ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT",
        "message": (
            "The private manifest probed has crossed the reparse-point-associated path."
        ),
    },
    0x000036C5: {
        "code": "ERROR_SXS_DUPLICATE_DLL_NAME",
        "message": (
            "Two or more components referenced directly or indirectly by the"
            " application manifest have files by the same name."
        ),
    },
    0x000036C6: {
        "code": "ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME",
        "message": (
            "Two or more components referenced directly or indirectly by the"
            " application manifest have window classes with the same name."
        ),
    },
    0x000036C7: {
        "code": "ERROR_SXS_DUPLICATE_CLSID",
        "message": (
            "Two or more components referenced directly or indirectly by the"
            " application manifest have the same COM server CLSIDs."
        ),
    },
    0x000036C8: {
        "code": "ERROR_SXS_DUPLICATE_IID",
        "message": (
            "Two or more components referenced directly or indirectly by the"
            " application manifest have proxies for the same COM interface IIDs."
        ),
    },
    0x000036C9: {
        "code": "ERROR_SXS_DUPLICATE_TLBID",
        "message": (
            "Two or more components referenced directly or indirectly by the"
            " application manifest have the same COM type library TLBIDs."
        ),
    },
    0x000036CA: {
        "code": "ERROR_SXS_DUPLICATE_PROGID",
        "message": (
            "Two or more components referenced directly or indirectly by the"
            " application manifest have the same COM ProgIDs."
        ),
    },
    0x000036CB: {
        "code": "ERROR_SXS_DUPLICATE_ASSEMBLY_NAME",
        "message": (
            "Two or more components referenced directly or indirectly by the"
            " application manifest are different versions of the same component, which"
            " is not permitted."
        ),
    },
    0x000036CC: {
        "code": "ERROR_SXS_FILE_HASH_MISMATCH",
        "message": (
            "A component's file does not match the verification information present in"
            " the component manifest."
        ),
    },
    0x000036CD: {
        "code": "ERROR_SXS_POLICY_PARSE_ERROR",
        "message": "The policy manifest contains one or more syntax errors.",
    },
    0x000036CE: {
        "code": "ERROR_SXS_XML_E_MISSINGQUOTE",
        "message": (
            "Manifest Parse Error: A string literal was expected, but no opening"
            " quotation mark was found."
        ),
    },
    0x000036CF: {
        "code": "ERROR_SXS_XML_E_COMMENTSYNTAX",
        "message": "Manifest Parse Error: Incorrect syntax was used in a comment.",
    },
    0x000036D0: {
        "code": "ERROR_SXS_XML_E_BADSTARTNAMECHAR",
        "message": "Manifest Parse Error: A name started with an invalid character.",
    },
    0x000036D1: {
        "code": "ERROR_SXS_XML_E_BADNAMECHAR",
        "message": "Manifest Parse Error: A name contained an invalid character.",
    },
    0x000036D2: {
        "code": "ERROR_SXS_XML_E_BADCHARINSTRING",
        "message": (
            "Manifest Parse Error: A string literal contained an invalid character."
        ),
    },
    0x000036D3: {
        "code": "ERROR_SXS_XML_E_XMLDECLSYNTAX",
        "message": "Manifest Parse Error: Invalid syntax for an XML declaration.",
    },
    0x000036D4: {
        "code": "ERROR_SXS_XML_E_BADCHARDATA",
        "message": (
            "Manifest Parse Error: An Invalid character was found in text content."
        ),
    },
    0x000036D5: {
        "code": "ERROR_SXS_XML_E_MISSINGWHITESPACE",
        "message": "Manifest Parse Error: Required white space was missing.",
    },
    0x000036D6: {
        "code": "ERROR_SXS_XML_E_EXPECTINGTAGEND",
        "message": (
            "Manifest Parse Error: The angle bracket (>) character was expected."
        ),
    },
    0x000036D7: {
        "code": "ERROR_SXS_XML_E_MISSINGSEMICOLON",
        "message": "Manifest Parse Error: A semicolon (;) was expected.",
    },
    0x000036D8: {
        "code": "ERROR_SXS_XML_E_UNBALANCEDPAREN",
        "message": "Manifest Parse Error: Unbalanced parentheses.",
    },
    0x000036D9: {
        "code": "ERROR_SXS_XML_E_INTERNALERROR",
        "message": "Manifest Parse Error: Internal error.",
    },
    0x000036DA: {
        "code": "ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE",
        "message": "Manifest Parse Error: Whitespace is not allowed at this location.",
    },
    0x000036DB: {
        "code": "ERROR_SXS_XML_E_INCOMPLETE_ENCODING",
        "message": (
            "Manifest Parse Error: End of file reached in invalid state for current"
            " encoding."
        ),
    },
    0x000036DC: {
        "code": "ERROR_SXS_XML_E_MISSING_PAREN",
        "message": "Manifest Parse Error: Missing parenthesis.",
    },
    0x000036DD: {
        "code": "ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE",
        "message": (
            "Manifest Parse Error: A single (') or double (\") quotation mark is"
            " missing."
        ),
    },
    0x000036DE: {
        "code": "ERROR_SXS_XML_E_MULTIPLE_COLONS",
        "message": "Manifest Parse Error: Multiple colons are not allowed in a name.",
    },
    0x000036DF: {
        "code": "ERROR_SXS_XML_E_INVALID_DECIMAL",
        "message": "Manifest Parse Error: Invalid character for decimal digit.",
    },
    0x000036E0: {
        "code": "ERROR_SXS_XML_E_INVALID_HEXIDECIMAL",
        "message": "Manifest Parse Error: Invalid character for hexadecimal digit.",
    },
    0x000036E1: {
        "code": "ERROR_SXS_XML_E_INVALID_UNICODE",
        "message": (
            "Manifest Parse Error: Invalid Unicode character value for this platform."
        ),
    },
    0x000036E2: {
        "code": "ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK",
        "message": "Manifest Parse Error: Expecting whitespace or question mark (?).",
    },
    0x000036E3: {
        "code": "ERROR_SXS_XML_E_UNEXPECTEDENDTAG",
        "message": "Manifest Parse Error: End tag was not expected at this location.",
    },
    0x000036E4: {
        "code": "ERROR_SXS_XML_E_UNCLOSEDTAG",
        "message": "Manifest Parse Error: The following tags were not closed: %1.",
    },
    0x000036E5: {
        "code": "ERROR_SXS_XML_E_DUPLICATEATTRIBUTE",
        "message": "Manifest Parse Error: Duplicate attribute.",
    },
    0x000036E6: {
        "code": "ERROR_SXS_XML_E_MULTIPLEROOTS",
        "message": (
            "Manifest Parse Error: Only one top-level element is allowed in an XML"
            " document."
        ),
    },
    0x000036E7: {
        "code": "ERROR_SXS_XML_E_INVALIDATROOTLEVEL",
        "message": "Manifest Parse Error: Invalid at the top level of the document.",
    },
    0x000036E8: {
        "code": "ERROR_SXS_XML_E_BADXMLDECL",
        "message": "Manifest Parse Error: Invalid XML declaration.",
    },
    0x000036E9: {
        "code": "ERROR_SXS_XML_E_MISSINGROOT",
        "message": "Manifest Parse Error: XML document must have a top-level element.",
    },
    0x000036EA: {
        "code": "ERROR_SXS_XML_E_UNEXPECTEDEOF",
        "message": "Manifest Parse Error: Unexpected end of file.",
    },
    0x000036EB: {
        "code": "ERROR_SXS_XML_E_BADPEREFINSUBSET",
        "message": (
            "Manifest Parse Error: Parameter entities cannot be used inside markup"
            " declarations in an internal subset."
        ),
    },
    0x000036EC: {
        "code": "ERROR_SXS_XML_E_UNCLOSEDSTARTTAG",
        "message": "Manifest Parse Error: Element was not closed.",
    },
    0x000036ED: {
        "code": "ERROR_SXS_XML_E_UNCLOSEDENDTAG",
        "message": (
            "Manifest Parse Error: End element was missing the angle bracket (>)"
            " character."
        ),
    },
    0x000036EE: {
        "code": "ERROR_SXS_XML_E_UNCLOSEDSTRING",
        "message": "Manifest Parse Error: A string literal was not closed.",
    },
    0x000036EF: {
        "code": "ERROR_SXS_XML_E_UNCLOSEDCOMMENT",
        "message": "Manifest Parse Error: A comment was not closed.",
    },
    0x000036F0: {
        "code": "ERROR_SXS_XML_E_UNCLOSEDDECL",
        "message": "Manifest Parse Error: A declaration was not closed.",
    },
    0x000036F1: {
        "code": "ERROR_SXS_XML_E_UNCLOSEDCDATA",
        "message": "Manifest Parse Error: A CDATA section was not closed.",
    },
    0x000036F2: {
        "code": "ERROR_SXS_XML_E_RESERVEDNAMESPACE",
        "message": (
            "Manifest Parse Error: The namespace prefix is not allowed to start with"
            ' the reserved string xml"."'
        ),
    },
    0x000036F3: {
        "code": "ERROR_SXS_XML_E_INVALIDENCODING",
        "message": (
            "Manifest Parse Error: System does not support the specified encoding."
        ),
    },
    0x000036F4: {
        "code": "ERROR_SXS_XML_E_INVALIDSWITCH",
        "message": (
            "Manifest Parse Error: Switch from current encoding to specified encoding"
            " not supported."
        ),
    },
    0x000036F5: {
        "code": "ERROR_SXS_XML_E_BADXMLCASE",
        "message": (
            'Manifest Parse Error: The name "xml" is reserved and must be lowercase.'
        ),
    },
    0x000036F6: {
        "code": "ERROR_SXS_XML_E_INVALID_STANDALONE",
        "message": (
            'Manifest Parse Error: The stand-alone attribute must have the value "yes"'
            ' or "no".'
        ),
    },
    0x000036F7: {
        "code": "ERROR_SXS_XML_E_UNEXPECTED_STANDALONE",
        "message": (
            "Manifest Parse Error: The stand-alone attribute cannot be used in external"
            " entities."
        ),
    },
    0x000036F8: {
        "code": "ERROR_SXS_XML_E_INVALID_VERSION",
        "message": "Manifest Parse Error: Invalid version number.",
    },
    0x000036F9: {
        "code": "ERROR_SXS_XML_E_MISSINGEQUALS",
        "message": (
            "Manifest Parse Error: Missing equal sign (=) between the attribute and the"
            " attribute value."
        ),
    },
    0x000036FA: {
        "code": "ERROR_SXS_PROTECTION_RECOVERY_FAILED",
        "message": (
            "Assembly Protection Error: Unable to recover the specified assembly."
        ),
    },
    0x000036FB: {
        "code": "ERROR_SXS_PROTECTION_PUBLIC_KEY_OO_SHORT",
        "message": (
            "Assembly Protection Error: The public key for an assembly was too short to"
            " be allowed."
        ),
    },
    0x000036FC: {
        "code": "ERROR_SXS_PROTECTION_CATALOG_NOT_VALID",
        "message": (
            "Assembly Protection Error: The catalog for an assembly is not valid, or"
            " does not match the assembly's manifest."
        ),
    },
    0x000036FD: {
        "code": "ERROR_SXS_UNTRANSLATABLE_HRESULT",
        "message": (
            "An HRESULT could not be translated to a corresponding Win32 error code."
        ),
    },
    0x000036FE: {
        "code": "ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING",
        "message": "Assembly Protection Error: The catalog for an assembly is missing.",
    },
    0x000036FF: {
        "code": "ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE",
        "message": (
            "The supplied assembly identity is missing one or more attributes that must"
            " be present in this context."
        ),
    },
    0x00003700: {
        "code": "ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME",
        "message": (
            "The supplied assembly identity has one or more attribute names that"
            " contain characters not permitted in XML names."
        ),
    },
    0x00003701: {
        "code": "ERROR_SXS_ASSEMBLY_MISSING",
        "message": "The referenced assembly could not be found.",
    },
    0x00003702: {
        "code": "ERROR_SXS_CORRUPT_ACTIVATION_STACK",
        "message": (
            "The activation context activation stack for the running thread of"
            " execution is corrupt."
        ),
    },
    0x00003703: {
        "code": "ERROR_SXS_CORRUPTION",
        "message": (
            "The application isolation metadata for this process or thread has become"
            " corrupt."
        ),
    },
    0x00003704: {
        "code": "ERROR_SXS_EARLY_DEACTIVATION",
        "message": (
            "The activation context being deactivated is not the most recently"
            " activated one."
        ),
    },
    0x00003705: {
        "code": "ERROR_SXS_INVALID_DEACTIVATION",
        "message": (
            "The activation context being deactivated is not active for the current"
            " thread of execution."
        ),
    },
    0x00003706: {
        "code": "ERROR_SXS_MULTIPLE_DEACTIVATION",
        "message": (
            "The activation context being deactivated has already been deactivated."
        ),
    },
    0x00003707: {
        "code": "ERROR_SXS_PROCESS_TERMINATION_REQUESTED",
        "message": (
            "A component used by the isolation facility has requested to terminate the"
            " process."
        ),
    },
    0x00003708: {
        "code": "ERROR_SXS_RELEASE_ACTIVATION_ONTEXT",
        "message": (
            "A kernel mode component is releasing a reference on an activation context."
        ),
    },
    0x00003709: {
        "code": "ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY",
        "message": (
            "The activation context of the system default assembly could not be"
            " generated."
        ),
    },
    0x0000370A: {
        "code": "ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE",
        "message": (
            "The value of an attribute in an identity is not within the legal range."
        ),
    },
    0x0000370B: {
        "code": "ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME",
        "message": (
            "The name of an attribute in an identity is not within the legal range."
        ),
    },
    0x0000370C: {
        "code": "ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE",
        "message": "An identity contains two definitions for the same attribute.",
    },
    0x0000370D: {
        "code": "ERROR_SXS_IDENTITY_PARSE_ERROR",
        "message": (
            "The identity string is malformed. This might be due to a trailing comma,"
            " more than two unnamed attributes, a missing attribute name, or a missing"
            " attribute value."
        ),
    },
    0x0000370E: {
        "code": "ERROR_MALFORMED_SUBSTITUTION_STRING",
        "message": (
            "A string containing localized substitutable content was malformed. Either"
            " a dollar sign ($) was followed by something other than a left parenthesis"
            " or another dollar sign, or a substitution's right parenthesis was not"
            " found."
        ),
    },
    0x0000370F: {
        "code": "ERROR_SXS_INCORRECT_PUBLIC_KEY_OKEN",
        "message": (
            "The public key token does not correspond to the public key specified."
        ),
    },
    0x00003710: {
        "code": "ERROR_UNMAPPED_SUBSTITUTION_STRING",
        "message": "A substitution string had no mapping.",
    },
    0x00003711: {
        "code": "ERROR_SXS_ASSEMBLY_NOT_LOCKED",
        "message": "The component must be locked before making the request.",
    },
    0x00003712: {
        "code": "ERROR_SXS_COMPONENT_STORE_CORRUPT",
        "message": "The component store has been corrupted.",
    },
    0x00003713: {
        "code": "ERROR_ADVANCED_INSTALLER_FAILED",
        "message": "An advanced installer failed during setup or servicing.",
    },
    0x00003714: {
        "code": "ERROR_XML_ENCODING_MISMATCH",
        "message": (
            "The character encoding in the XML declaration did not match the encoding"
            " used in the document."
        ),
    },
    0x00003715: {
        "code": "ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT",
        "message": (
            "The identities of the manifests are identical, but the contents are"
            " different."
        ),
    },
    0x00003716: {
        "code": "ERROR_SXS_IDENTITIES_DIFFERENT",
        "message": "The component identities are different.",
    },
    0x00003717: {
        "code": "ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT",
        "message": "The assembly is not a deployment.",
    },
    0x00003718: {
        "code": "ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY",
        "message": "The file is not a part of the assembly.",
    },
    0x00003719: {
        "code": "ERROR_SXS_MANIFEST_TOO_BIG",
        "message": "The size of the manifest exceeds the maximum allowed.",
    },
    0x0000371A: {
        "code": "ERROR_SXS_SETTING_NOT_REGISTERED",
        "message": "The setting is not registered.",
    },
    0x0000371B: {
        "code": "ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE",
        "message": "One or more required members of the transaction are not present.",
    },
    0x00003A98: {
        "code": "ERROR_EVT_INVALID_CHANNEL_PATH",
        "message": "The specified channel path is invalid.",
    },
    0x00003A99: {
        "code": "ERROR_EVT_INVALID_QUERY",
        "message": "The specified query is invalid.",
    },
    0x00003A9A: {
        "code": "ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND",
        "message": "The publisher metadata cannot be found in the resource.",
    },
    0x00003A9B: {
        "code": "ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND",
        "message": (
            "The template for an event definition cannot be found in the resource"
            " (error = %1)."
        ),
    },
    0x00003A9C: {
        "code": "ERROR_EVT_INVALID_PUBLISHER_NAME",
        "message": "The specified publisher name is invalid.",
    },
    0x00003A9D: {
        "code": "ERROR_EVT_INVALID_EVENT_DATA",
        "message": (
            "The event data raised by the publisher is not compatible with the event"
            " template definition in the publisher's manifest."
        ),
    },
    0x00003A9F: {
        "code": "ERROR_EVT_CHANNEL_NOT_FOUND",
        "message": (
            "The specified channel could not be found. Check channel configuration."
        ),
    },
    0x00003AA0: {
        "code": "ERROR_EVT_MALFORMED_XML_TEXT",
        "message": (
            "The specified XML text was not well-formed. See extended error for more"
            " details."
        ),
    },
    0x00003AA1: {
        "code": "ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL",
        "message": (
            "The caller is trying to subscribe to a direct channel which is not"
            " allowed. The events for a direct channel go directly to a log file and"
            " cannot be subscribed to."
        ),
    },
    0x00003AA2: {
        "code": "ERROR_EVT_CONFIGURATION_ERROR",
        "message": "Configuration error.",
    },
    0x00003AA3: {
        "code": "ERROR_EVT_QUERY_RESULT_STALE",
        "message": (
            "The query result is stale or invalid. This might be due to the log being"
            " cleared or rolling over after the query result was created. Users should"
            " handle this code by releasing the query result object and reissuing the"
            " query."
        ),
    },
    0x00003AA4: {
        "code": "ERROR_EVT_QUERY_RESULT_INVALID_POSITION",
        "message": "Query result is currently at an invalid position.",
    },
    0x00003AA5: {
        "code": "ERROR_EVT_NON_VALIDATING_MSXML",
        "message": "Registered Microsoft XML (MSXML) does not support validation.",
    },
    0x00003AA6: {
        "code": "ERROR_EVT_FILTER_ALREADYSCOPED",
        "message": (
            "An expression can only be followed by a change-of-scope operation if it"
            " itself evaluates to a node set and is not already part of some other"
            " change-of-scope operation."
        ),
    },
    0x00003AA7: {
        "code": "ERROR_EVT_FILTER_NOTELTSET",
        "message": (
            "Cannot perform a step operation from a term that does not represent an"
            " element set."
        ),
    },
    0x00003AA8: {
        "code": "ERROR_EVT_FILTER_INVARG",
        "message": (
            "Left side arguments to binary operators must be either attributes, nodes,"
            " or variables and right side arguments must be constants."
        ),
    },
    0x00003AA9: {
        "code": "ERROR_EVT_FILTER_INVTEST",
        "message": (
            "A step operation must involve either a node test or, in the case of a"
            " predicate, an algebraic expression against which to test each node in the"
            " node set identified by the preceding node set can be evaluated."
        ),
    },
    0x00003AAA: {
        "code": "ERROR_EVT_FILTER_INVTYPE",
        "message": "This data type is currently unsupported.",
    },
    0x00003AAB: {
        "code": "ERROR_EVT_FILTER_PARSEERR",
        "message": "A syntax error occurred at position %1!d!",
    },
    0x00003AAC: {
        "code": "ERROR_EVT_FILTER_UNSUPPORTEDOP",
        "message": "This operator is unsupported by this implementation of the filter.",
    },
    0x00003AAD: {
        "code": "ERROR_EVT_FILTER_UNEXPECTEDTOKEN",
        "message": "The token encountered was unexpected.",
    },
    0x00003AAE: {
        "code": "ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL",
        "message": (
            "The requested operation cannot be performed over an enabled direct"
            " channel. The channel must first be disabled before performing the"
            " requested operation."
        ),
    },
    0x00003AAF: {
        "code": "ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE",
        "message": (
            "Channel property %1!s! contains an invalid value. The value has an invalid"
            " type, is outside the valid range, cannot be updated, or is not supported"
            " by this type of channel."
        ),
    },
    0x00003AB0: {
        "code": "ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE",
        "message": (
            "Publisher property %1!s! contains an invalid value. The value has an"
            " invalid type, is outside the valid range, cannot be updated, or is not"
            " supported by this type of publisher."
        ),
    },
    0x00003AB1: {
        "code": "ERROR_EVT_CHANNEL_CANNOT_ACTIVATE",
        "message": "The channel fails to activate.",
    },
    0x00003AB2: {
        "code": "ERROR_EVT_FILTER_TOO_COMPLEX",
        "message": (
            "The xpath expression exceeded supported complexity. Simplify it or split"
            " it into two or more simple expressions."
        ),
    },
    0x00003AB3: {
        "code": "ERROR_EVT_MESSAGE_NOT_FOUND",
        "message": (
            "The message resource is present but the message is not found in the string"
            " or message table."
        ),
    },
    0x00003AB4: {
        "code": "ERROR_EVT_MESSAGE_ID_NOT_FOUND",
        "message": "The message ID for the desired message could not be found.",
    },
    0x00003AB5: {
        "code": "ERROR_EVT_UNRESOLVED_VALUE_INSERT",
        "message": (
            "The substitution string for the insert index (%1) could not be found."
        ),
    },
    0x00003AB6: {
        "code": "ERROR_EVT_UNRESOLVED_PARAMETER_INSERT",
        "message": (
            "The description string for the parameter reference (%1) could not be"
            " found."
        ),
    },
    0x00003AB7: {
        "code": "ERROR_EVT_MAX_INSERTS_REACHED",
        "message": "The maximum number of replacements has been reached.",
    },
    0x00003AB8: {
        "code": "ERROR_EVT_EVENT_DEFINITION_NOT_OUND",
        "message": "The event definition could not be found for the event ID (%1).",
    },
    0x00003AB9: {
        "code": "ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND",
        "message": (
            "The locale-specific resource for the desired message is not present."
        ),
    },
    0x00003ABA: {
        "code": "ERROR_EVT_VERSION_TOO_OLD",
        "message": "The resource is too old to be compatible.",
    },
    0x00003ABB: {
        "code": "ERROR_EVT_VERSION_TOO_NEW",
        "message": "The resource is too new to be compatible.",
    },
    0x00003ABC: {
        "code": "ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY",
        "message": "The channel at index %1 of the query cannot be opened.",
    },
    0x00003ABD: {
        "code": "ERROR_EVT_PUBLISHER_DISABLED",
        "message": (
            "The publisher has been disabled and its resource is not available. This"
            " usually occurs when the publisher is in the process of being uninstalled"
            " or upgraded."
        ),
    },
    0x00003AE8: {
        "code": "ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE",
        "message": "The subscription fails to activate.",
    },
    0x00003AE9: {
        "code": "ERROR_EC_LOG_DISABLED",
        "message": (
            "The log of the subscription is in a disabled state and events cannot be"
            " forwarded to it. The log must first be enabled before the subscription"
            " can be activated."
        ),
    },
    0x00003AFC: {
        "code": "ERROR_MUI_FILE_NOT_FOUND",
        "message": (
            "The resource loader failed to find the Multilingual User Interface (MUI)"
            " file."
        ),
    },
    0x00003AFD: {
        "code": "ERROR_MUI_INVALID_FILE",
        "message": (
            "The resource loader failed to load the MUI file because the file failed to"
            " pass validation."
        ),
    },
    0x00003AFE: {
        "code": "ERROR_MUI_INVALID_RC_CONFIG",
        "message": (
            "The release candidate (RC) manifest is corrupted with garbage data, is an"
            " unsupported version, or is missing a required item."
        ),
    },
    0x00003AFF: {
        "code": "ERROR_MUI_INVALID_LOCALE_NAME",
        "message": "The RC manifest has an invalid culture name.",
    },
    0x00003B00: {
        "code": "ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME",
        "message": "The RC Manifest has an invalid ultimate fallback name.",
    },
    0x00003B01: {
        "code": "ERROR_MUI_FILE_NOT_LOADED",
        "message": "The resource loader cache does not have a loaded MUI entry.",
    },
    0x00003B02: {
        "code": "ERROR_RESOURCE_ENUM_USER_STOP",
        "message": "The user stopped resource enumeration.",
    },
    0x00003B03: {
        "code": "ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED",
        "message": "User interface language installation failed.",
    },
    0x00003B04: {
        "code": "ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME",
        "message": "Locale installation failed.",
    },
    0x00003B60: {
        "code": "ERROR_MCA_INVALID_CAPABILITIES_STRING",
        "message": (
            "The monitor returned a DDC/CI capabilities string that did not comply with"
            " the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification."
        ),
    },
    0x00003B61: {
        "code": "ERROR_MCA_INVALID_VCP_VERSION",
        "message": (
            "The monitor's VCP version (0xDF) VCP code returned an invalid version"
            " value."
        ),
    },
    0x00003B62: {
        "code": "ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION",
        "message": (
            "The monitor does not comply with the MCCS specification it claims to"
            " support."
        ),
    },
    0x00003B63: {
        "code": "ERROR_MCA_MCCS_VERSION_MISMATCH",
        "message": (
            "The MCCS version in a monitor's mccs_ver capability does not match the"
            " MCCS version the monitor reports when the VCP version (0xDF) VCP code is"
            " used."
        ),
    },
    0x00003B64: {
        "code": "ERROR_MCA_UNSUPPORTED_MCCS_VERSION",
        "message": (
            "The monitor configuration API works only with monitors that support the"
            " MCCS 1.0, MCCS 2.0, or MCCS 2.0 Revision 1 specifications."
        ),
    },
    0x00003B65: {
        "code": "ERROR_MCA_INTERNAL_ERROR",
        "message": "An internal monitor configuration API error occurred.",
    },
    0x00003B66: {
        "code": "ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED",
        "message": (
            "The monitor returned an invalid monitor technology type. CRT, plasma, and"
            " LCD (TFT) are examples of monitor technology types. This error implies"
            " that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1"
            " specification."
        ),
    },
    0x00003B67: {
        "code": "ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE",
        "message": (
            "The SetMonitorColorTemperature() caller passed a color temperature to it"
            " that the current monitor did not support. CRT, plasma, and LCD (TFT) are"
            " examples of monitor technology types. This error implies that the monitor"
            " violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification."
        ),
    },
    0x00003B92: {
        "code": "ERROR_AMBIGUOUS_SYSTEM_DEVICE",
        "message": (
            "The requested system device cannot be identified due to multiple"
            " indistinguishable devices potentially matching the identification"
            " criteria."
        ),
    },
    0x00003BC3: {
        "code": "ERROR_SYSTEM_DEVICE_NOT_FOUND",
        "message": "The requested system device cannot be found.",
    },
}

HRESULT = {
    0x00030200: { "code": "STG_S_CONVERTED", "message":"The underlying file was converted to compound file format."},

0x00030201: { "code": "STG_S_BLOCK", "message":"The storage operation should block until more data is available."},

0x00030202: { "code": "STG_S_RETRYNOW", "message":"The storage operation should retry immediately."},

0x00030203: { "code": "STG_S_MONITORING", "message":"The notified event sink will not influence the storage operation."},

0x00030204: { "code": "STG_S_MULTIPLEOPENS", "message":"Multiple opens prevent consolidated (commit succeeded)."},

0x00030205: { "code": "STG_S_CONSOLIDATIONFAILED", "message":"Consolidation of the storage file failed (commit succeeded)."},

0x00030206: { "code": "STG_S_CANNOTCONSOLIDATE", "message":"Consolidation of the storage file is inappropriate (commit succeeded)."},

0x00040000: { "code": "OLE_S_USEREG", "message":"Use the registry database to provide the requested information."},

0x00040001: { "code": "OLE_S_STATIC", "message":"Success, but static."},

0x00040002: { "code": "OLE_S_MAC_CLIPFORMAT", "message":"Macintosh clipboard format."},

0x00040100: { "code": "DRAGDROP_S_DROP", "message":"Successful drop took place."},

0x00040101: { "code": "DRAGDROP_S_CANCEL", "message":"Drag-drop operation canceled."},

0x00040102: { "code": "DRAGDROP_S_USEDEFAULTCURSORS", "message":"Use the default cursor."},

0x00040130: { "code": "DATA_S_SAMEFORMATETC", "message":"Data has same FORMATETC."},

0x00040140: { "code": "VIEW_S_ALREADY_FROZEN", "message":"View is already frozen."},

0x00040170: { "code": "CACHE_S_FORMATETC_NOTSUPPORTED", "message":"FORMATETC not supported."},

0x00040171: { "code": "CACHE_S_SAMECACHE", "message":"Same cache."},

0x00040172: { "code": "CACHE_S_SOMECACHES_NOTUPDATED", "message":"Some caches are not updated."},

0x00040180: { "code": "OLEOBJ_S_INVALIDVERB", "message":"Invalid verb for OLE object."},

0x00040181: { "code": "OLEOBJ_S_CANNOT_DOVERB_NOW", "message":"Verb number is valid but verb cannot be done now."},

0x00040182: { "code": "OLEOBJ_S_INVALIDHWND", "message":"Invalid window handle passed."},

0x000401A0: { "code": "INPLACE_S_TRUNCATED", "message":"Message is too long; some of it had to be truncated before displaying."},

0x000401C0: { "code": "CONVERT10_S_NO_PRESENTATION", "message":"Unable to convert OLESTREAM to IStorage."},

0x000401E2: { "code": "MK_S_REDUCED_TO_SELF", "message":"Moniker reduced to itself."},

0x000401E4: { "code": "MK_S_ME", "message":"Common prefix is this moniker."},

0x000401E5: { "code": "MK_S_HIM", "message":"Common prefix is input moniker."},

0x000401E6: { "code": "MK_S_US", "message":"Common prefix is both monikers."},

0x000401E7: { "code": "MK_S_MONIKERALREADYREGISTERED", "message":"Moniker is already registered in running object table."},

0x00040200: { "code": "EVENT_S_SOME_SUBSCRIBERS_FAILED", "message":"An event was able to invoke some, but not all, of the subscribers."},

0x00040202: { "code": "EVENT_S_NOSUBSCRIBERS", "message":"An event was delivered, but there were no subscribers."},

0x00041300: { "code": "SCHED_S_TASK_READY", "message":"The task is ready to run at its next scheduled time."},

0x00041301: { "code": "SCHED_S_TASK_RUNNING", "message":"The task is currently running."},

0x00041302: { "code": "SCHED_S_TASK_DISABLED", "message":"The task will not run at the scheduled times because it has been disabled."},

0x00041303: { "code": "SCHED_S_TASK_HAS_NOT_RUN", "message":"The task has not yet run."},

0x00041304: { "code": "SCHED_S_TASK_NO_MORE_RUNS", "message":"There are no more runs scheduled for this task."},

0x00041305: { "code": "SCHED_S_TASK_NOT_SCHEDULED", "message":"One or more of the properties that are needed to run this task on a schedule have not been set."},

0x00041306: { "code": "SCHED_S_TASK_TERMINATED", "message":"The last run of the task was terminated by the user."},

0x00041307: { "code": "SCHED_S_TASK_NO_VALID_TRIGGERS", "message":"Either the task has no triggers, or the existing triggers are disabled or not set."},

0x00041308: { "code": "SCHED_S_EVENT_TRIGGER", "message":"Event triggers do not have set run times."},

0x0004131B: { "code": "SCHED_S_SOME_TRIGGERS_FAILED", "message":"The task is registered, but not all specified triggers will start the task."},

0x0004131C: { "code": "SCHED_S_BATCH_LOGON_PROBLEM", "message":"The task is registered, but it might fail to start. Batch logon privilege needs to be enabled for the task principal."},

0x0004D000: { "code": "XACT_S_ASYNC", "message":"An asynchronous operation was specified. The operation has begun, but its outcome is not known yet."},

0x0004D002: { "code": "XACT_S_READONLY", "message":"The method call succeeded because the transaction was read-only."},

0x0004D003: { "code": "XACT_S_SOMENORETAIN", "message":"The transaction was successfully aborted. However, this is a coordinated transaction, and a number of enlisted resources were aborted outright because they could not support abort-retaining semantics."},

0x0004D004: { "code": "XACT_S_OKINFORM", "message":"No changes were made during this call, but the sink wants another chance to look if any other sinks make further changes."},

0x0004D005: { "code": "XACT_S_MADECHANGESCONTENT", "message":"The sink is content and wants the transaction to proceed. Changes were made to one or more resources during this call."},

0x0004D006: { "code": "XACT_S_MADECHANGESINFORM", "message":"The sink is for the moment and wants the transaction to proceed, but if other changes are made following this return by other event sinks, this sink wants another chance to look."},

0x0004D007: { "code": "XACT_S_ALLNORETAIN", "message":"The transaction was successfully aborted. However, the abort was nonretaining."},

0x0004D008: { "code": "XACT_S_ABORTING", "message":"An abort operation was already in progress."},

0x0004D009: { "code": "XACT_S_SINGLEPHASE", "message":"The resource manager has performed a single-phase commit of the transaction."},

0x0004D00A: { "code": "XACT_S_LOCALLY_OK", "message":"The local transaction has not aborted."},

0x0004D010: { "code": "XACT_S_LASTRESOURCEMANAGER", "message":"The resource manager has requested to be the coordinator (last resource manager) for the transaction."},

0x00080012: { "code": "CO_S_NOTALLINTERFACES", "message":"Not all the requested interfaces were available."},

0x00080013: { "code": "CO_S_MACHINENAMENOTFOUND", "message":"The specified machine name was not found in the cache."},

0x00090312: { "code": "SEC_I_CONTINUE_NEEDED", "message":"The function completed successfully, but it must be called again to complete the context."},

0x00090313: { "code": "SEC_I_COMPLETE_NEEDED", "message":"The function completed successfully, but CompleteToken must be called."},

0x00090314: { "code": "SEC_I_COMPLETE_AND_CONTINUE", "message":"The function completed successfully, but both CompleteToken and this function must be called to complete the context."},

0x00090315: { "code": "SEC_I_LOCAL_LOGON", "message":"The logon was completed, but no network authority was available. The logon was made using locally known information."},

0x00090317: { "code": "SEC_I_CONTEXT_EXPIRED", "message":"The context has expired and can no longer be used."},

0x00090320: { "code": "SEC_I_INCOMPLETE_CREDENTIALS", "message":"The credentials supplied were not complete and could not be verified. Additional information can be returned from the context."},

0x00090321: { "code": "SEC_I_RENEGOTIATE", "message":"The context data must be renegotiated with the peer."},

0x00090323: { "code": "SEC_I_NO_LSA_CONTEXT", "message":"There is no LSA mode context associated with this context."},

0x0009035C: { "code": "SEC_I_SIGNATURE_NEEDED", "message":"A signature operation must be performed before the user can authenticate."},

0x00091012: { "code": "CRYPT_I_NEW_PROTECTION_REQUIRED", "message":"The protected data needs to be reprotected."},

0x000D0000: { "code": "NS_S_CALLPENDING", "message":"The requested operation is pending completion."},

0x000D0001: { "code": "NS_S_CALLABORTED", "message":"The requested operation was aborted by the client."},

0x000D0002: { "code": "NS_S_STREAM_TRUNCATED", "message":"The stream was purposefully stopped before completion."},

0x000D0BC8: { "code": "NS_S_REBUFFERING", "message":"The requested operation has caused the source to rebuffer."},

0x000D0BC9: { "code": "NS_S_DEGRADING_QUALITY", "message":"The requested operation has caused the source to degrade codec quality."},

0x000D0BDB: { "code": "NS_S_TRANSCRYPTOR_EOF", "message":"The transcryptor object has reached end of file."},

0x000D0FE8: { "code": "NS_S_WMP_UI_VERSIONMISMATCH", "message":"An upgrade is needed for the theme manager to correctly show this skin. Skin reports version: %.1f."},

0x000D0FE9: { "code": "NS_S_WMP_EXCEPTION", "message":"An error occurred in one of the UI components."},

0x000D1040: { "code": "NS_S_WMP_LOADED_GIF_IMAGE", "message":"Successfully loaded a GIF file."},

0x000D1041: { "code": "NS_S_WMP_LOADED_PNG_IMAGE", "message":"Successfully loaded a PNG file."},

0x000D1042: { "code": "NS_S_WMP_LOADED_BMP_IMAGE", "message":"Successfully loaded a BMP file."},

0x000D1043: { "code": "NS_S_WMP_LOADED_JPG_IMAGE", "message":"Successfully loaded a JPG file."},

0x000D104F: { "code": "NS_S_WMG_FORCE_DROP_FRAME", "message":"Drop this frame."},

0x000D105F: { "code": "NS_S_WMR_ALREADYRENDERED", "message":"The specified stream has already been rendered."},

0x000D1060: { "code": "NS_S_WMR_PINTYPEPARTIALMATCH", "message":"The specified type partially matches this pin type."},

0x000D1061: { "code": "NS_S_WMR_PINTYPEFULLMATCH", "message":"The specified type fully matches this pin type."},

0x000D1066: { "code": "NS_S_WMG_ADVISE_DROP_FRAME", "message":"The timestamp is late compared to the current render position. Advise dropping this frame."},

0x000D1067: { "code": "NS_S_WMG_ADVISE_DROP_TO_KEYFRAME", "message":"The timestamp is severely late compared to the current render position. Advise dropping everything up to the next key frame."},

0x000D10DB: { "code": "NS_S_NEED_TO_BUY_BURN_RIGHTS", "message":"No burn rights. You will be prompted to buy burn rights when you try to burn this file to an audio CD."},

0x000D10FE: { "code": "NS_S_WMPCORE_PLAYLISTCLEARABORT", "message":"Failed to clear playlist because it was aborted by user."},

0x000D10FF: { "code": "NS_S_WMPCORE_PLAYLISTREMOVEITEMABORT", "message":"Failed to remove item in the playlist since it was aborted by user."},

0x000D1102: { "code": "NS_S_WMPCORE_PLAYLIST_CREATION_PENDING", "message":"Playlist is being generated asynchronously."},

0x000D1103: { "code": "NS_S_WMPCORE_MEDIA_VALIDATION_PENDING", "message":"Validation of the media is pending."},

0x000D1104: { "code": "NS_S_WMPCORE_PLAYLIST_REPEAT_SECONDARY_SEGMENTS_IGNORED", "message":"Encountered more than one Repeat block during ASX processing."},

0x000D1105: { "code": "NS_S_WMPCORE_COMMAND_NOT_AVAILABLE", "message":"Current state of WMP disallows calling this method or property."},

0x000D1106: { "code": "NS_S_WMPCORE_PLAYLIST_NAME_AUTO_GENERATED", "message":"Name for the playlist has been auto generated."},

0x000D1107: { "code": "NS_S_WMPCORE_PLAYLIST_IMPORT_MISSING_ITEMS", "message":"The imported playlist does not contain all items from the original."},

0x000D1108: { "code": "NS_S_WMPCORE_PLAYLIST_COLLAPSED_TO_SINGLE_MEDIA", "message":"The M3U playlist has been ignored because it only contains one item."},

0x000D1109: { "code": "NS_S_WMPCORE_MEDIA_CHILD_PLAYLIST_OPEN_PENDING", "message":"The open for the child playlist associated with this media is pending."},

0x000D110A: { "code": "NS_S_WMPCORE_MORE_NODES_AVAIABLE", "message":"More nodes support the interface requested, but the array for returning them is full."},

0x000D1135: { "code": "NS_S_WMPBR_SUCCESS", "message":"Backup or Restore successful!."},

0x000D1136: { "code": "NS_S_WMPBR_PARTIALSUCCESS", "message":"Transfer complete with limitations."},

0x000D1144: { "code": "NS_S_WMPEFFECT_TRANSPARENT", "message":"Request to the effects control to change transparency status to transparent."},

0x000D1145: { "code": "NS_S_WMPEFFECT_OPAQUE", "message":"Request to the effects control to change transparency status to opaque."},

0x000D114E: { "code": "NS_S_OPERATION_PENDING", "message":"The requested application pane is performing an operation and will not be released."},

0x000D1359: { "code": "NS_S_TRACK_BUY_REQUIRES_ALBUM_PURCHASE", "message":"The file is only available for purchase when you buy the entire album."},

0x000D135E: { "code": "NS_S_NAVIGATION_COMPLETE_WITH_ERRORS", "message":"There were problems completing the requested navigation. There are identifiers missing in the catalog."},

0x000D1361: { "code": "NS_S_TRACK_ALREADY_DOWNLOADED", "message":"Track already downloaded."},

0x000D1519: { "code": "NS_S_PUBLISHING_POINT_STARTED_WITH_FAILED_SINKS", "message":"The publishing point successfully started, but one or more of the requested data writer plug-ins failed."},

0x000D2726: { "code": "NS_S_DRM_LICENSE_ACQUIRED", "message":"Status message: The license was acquired."},

0x000D2727: { "code": "NS_S_DRM_INDIVIDUALIZED", "message":"Status message: The security upgrade has been completed."},

0x000D2746: { "code": "NS_S_DRM_MONITOR_CANCELLED", "message":"Status message: License monitoring has been canceled."},

0x000D2747: { "code": "NS_S_DRM_ACQUIRE_CANCELLED", "message":"Status message: License acquisition has been canceled."},

0x000D276E: { "code": "NS_S_DRM_BURNABLE_TRACK", "message":"The track is burnable and had no playlist burn limit."},

0x000D276F: { "code": "NS_S_DRM_BURNABLE_TRACK_WITH_PLAYLIST_RESTRICTION", "message":"The track is burnable but has a playlist burn limit."},

0x000D27DE: { "code": "NS_S_DRM_NEEDS_INDIVIDUALIZATION", "message":"A security upgrade is required to perform the operation on this media file."},

0x000D2AF8: { "code": "NS_S_REBOOT_RECOMMENDED", "message":"Installation was successful; however, some file cleanup is not complete. For best results, restart your computer."},

0x000D2AF9: { "code": "NS_S_REBOOT_REQUIRED", "message":"Installation was successful; however, some file cleanup is not complete. To continue, you must restart your computer."},

0x000D2F09: { "code": "NS_S_EOSRECEDING", "message":"EOS hit during rewinding."},

0x000D2F0D: { "code": "NS_S_CHANGENOTICE", "message":"Internal."},

0x001F0001: { "code": "ERROR_FLT_IO_COMPLETE", "message":"The IO was completed by a filter."},

0x00262307: { "code": "ERROR_GRAPHICS_MODE_NOT_PINNED", "message":"No mode is pinned on the specified VidPN source or target."},

0x0026231E: { "code": "ERROR_GRAPHICS_NO_PREFERRED_MODE", "message":"Specified mode set does not specify preference for one of its modes."},

0x0026234B: { "code": "ERROR_GRAPHICS_DATASET_IS_EMPTY", "message":"Specified data set (for example, mode set, frequency range set, descriptor set, and topology) is empty."},

0x0026234C: { "code": "ERROR_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET", "message":"Specified data set (for example, mode set, frequency range set, descriptor set, and topology) does not contain any more elements."},

0x00262351: { "code": "ERROR_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED", "message":"Specified content transformation is not pinned on the specified VidPN present path."},

0x00300100: { "code": "PLA_S_PROPERTY_IGNORED", "message":"Property value will be ignored."},

0x00340001: { "code": "ERROR_NDIS_INDICATION_REQUIRED", "message":"The request will be completed later by a Network Driver Interface Specification (NDIS) status indication."},

0x0DEAD100: { "code": "TRK_S_OUT_OF_SYNC", "message":"The VolumeSequenceNumber of a MOVE_NOTIFICATION request is incorrect."},

0x0DEAD102: { "code": "TRK_VOLUME_NOT_FOUND", "message":"The VolumeID in a request was not found in the server's ServerVolumeTable."},

0x0DEAD103: { "code": "TRK_VOLUME_NOT_OWNED", "message":"A notification was sent to the LnkSvrMessage method, but the RequestMachine for the request was not the VolumeOwner for a VolumeID in the request."},

0x0DEAD107: { "code": "TRK_S_NOTIFICATION_QUOTA_EXCEEDED", "message":"The server received a MOVE_NOTIFICATION request, but the FileTable size limit has already been reached."},

0x400D004F: { "code": "NS_I_TIGER_START", "message":"The Title Server %1 is running."},

0x400D0051: { "code": "NS_I_CUB_START", "message":"Content Server %1 (%2) is starting."},

0x400D0052: { "code": "NS_I_CUB_RUNNING", "message":"Content Server %1 (%2) is running."},

0x400D0054: { "code": "NS_I_DISK_START", "message":"Disk %1 ( %2 ) on Content Server %3, is running."},

0x400D0056: { "code": "NS_I_DISK_REBUILD_STARTED", "message":"Started rebuilding disk %1 ( %2 ) on Content Server %3."},

0x400D0057: { "code": "NS_I_DISK_REBUILD_FINISHED", "message":"Finished rebuilding disk %1 ( %2 ) on Content Server %3."},

0x400D0058: { "code": "NS_I_DISK_REBUILD_ABORTED", "message":"Aborted rebuilding disk %1 ( %2 ) on Content Server %3."},

0x400D0059: { "code": "NS_I_LIMIT_FUNNELS", "message":"A NetShow administrator at network location %1 set the data stream limit to %2 streams."},

0x400D005A: { "code": "NS_I_START_DISK", "message":"A NetShow administrator at network location %1 started disk %2."},

0x400D005B: { "code": "NS_I_STOP_DISK", "message":"A NetShow administrator at network location %1 stopped disk %2."},

0x400D005C: { "code": "NS_I_STOP_CUB", "message":"A NetShow administrator at network location %1 stopped Content Server %2."},

0x400D005D: { "code": "NS_I_KILL_USERSESSION", "message":"A NetShow administrator at network location %1 aborted user session %2 from the system."},

0x400D005E: { "code": "NS_I_KILL_CONNECTION", "message":"A NetShow administrator at network location %1 aborted obsolete connection %2 from the system."},

0x400D005F: { "code": "NS_I_REBUILD_DISK", "message":"A NetShow administrator at network location %1 started rebuilding disk %2."},

0x400D0069: { "code": "MCMADM_I_NO_EVENTS", "message":"Event initialization failed, there will be no MCM events."},

0x400D006E: { "code": "NS_I_LOGGING_FAILED", "message":"The logging operation failed."},

0x400D0070: { "code": "NS_I_LIMIT_BANDWIDTH", "message":"A NetShow administrator at network location %1 set the maximum bandwidth limit to %2 bps."},

0x400D0191: { "code": "NS_I_CUB_UNFAIL_LINK", "message":"Content Server %1 (%2) has established its link to Content Server %3."},

0x400D0193: { "code": "NS_I_RESTRIPE_START", "message":"Restripe operation has started."},

0x400D0194: { "code": "NS_I_RESTRIPE_DONE", "message":"Restripe operation has completed."},

0x400D0196: { "code": "NS_I_RESTRIPE_DISK_OUT", "message":"Content disk %1 (%2) on Content Server %3 has been restriped out."},

0x400D0197: { "code": "NS_I_RESTRIPE_CUB_OUT", "message":"Content server %1 (%2) has been restriped out."},

0x400D0198: { "code": "NS_I_DISK_STOP", "message":"Disk %1 ( %2 ) on Content Server %3, has been offlined."},

0x400D14BE: { "code": "NS_I_PLAYLIST_CHANGE_RECEDING", "message":"The playlist change occurred while receding."},

0x400D2EFF: { "code": "NS_I_RECONNECTED", "message":"The client is reconnected."},

0x400D2F01: { "code": "NS_I_NOLOG_STOP", "message":"Forcing a switch to a pending header on start."},

0x400D2F03: { "code": "NS_I_EXISTING_PACKETIZER", "message":"There is already an existing packetizer plugin for the stream."},

0x400D2F04: { "code": "NS_I_MANUAL_PROXY", "message":"The proxy setting is manual."},

0x40262009: { "code": "ERROR_GRAPHICS_DRIVER_MISMATCH", "message":"The kernel driver detected a version mismatch between it and the user mode driver."},

0x4026242F: { "code": "ERROR_GRAPHICS_UNKNOWN_CHILD_STATUS", "message":"Child device presence was not reliably detected."},

0x40262437: { "code": "ERROR_GRAPHICS_LEADLINK_START_DEFERRED", "message":"Starting the lead-link adapter has been deferred temporarily."},

0x40262439: { "code": "ERROR_GRAPHICS_POLLING_TOO_FREQUENTLY", "message":"The display adapter is being polled for children too frequently at the same polling level."},

0x4026243A: { "code": "ERROR_GRAPHICS_START_DEFERRED", "message":"Starting the adapter has been deferred temporarily."},

0x8000000A: { "code": "E_PENDING", "message":"The data necessary to complete this operation is not yet available."},

0x80004001: { "code": "E_NOTIMPL", "message":"Not implemented."},

0x80004002: { "code": "E_NOINTERFACE", "message":"No such interface supported."},

0x80004003: { "code": "E_POINTER", "message":"Invalid pointer."},

0x80004004: { "code": "E_ABORT", "message":"Operation aborted."},

0x80004005: { "code": "E_FAIL", "message":"Unspecified error."},

0x80004006: { "code": "CO_E_INIT_TLS", "message":"Thread local storage failure."},

0x80004007: { "code": "CO_E_INIT_SHARED_ALLOCATOR", "message":"Get shared memory allocator failure."},

0x80004008: { "code": "CO_E_INIT_MEMORY_ALLOCATOR", "message":"Get memory allocator failure."},

0x80004009: { "code": "CO_E_INIT_CLASS_CACHE", "message":"Unable to initialize class cache."},

0x8000400A: { "code": "CO_E_INIT_RPC_CHANNEL", "message":"Unable to initialize remote procedure call (RPC) services."},

0x8000400B: { "code": "CO_E_INIT_TLS_SET_CHANNEL_CONTROL", "message":"Cannot set thread local storage channel control."},

0x8000400C: { "code": "CO_E_INIT_TLS_CHANNEL_CONTROL", "message":"Could not allocate thread local storage channel control."},

0x8000400D: { "code": "CO_E_INIT_UNACCEPTED_USER_ALLOCATOR", "message":"The user-supplied memory allocator is unacceptable."},

0x8000400E: { "code": "CO_E_INIT_SCM_MUTEX_EXISTS", "message":"The OLE service mutex already exists."},

0x8000400F: { "code": "CO_E_INIT_SCM_FILE_MAPPING_EXISTS", "message":"The OLE service file mapping already exists."},

0x80004010: { "code": "CO_E_INIT_SCM_MAP_VIEW_OF_FILE", "message":"Unable to map view of file for OLE service."},

0x80004011: { "code": "CO_E_INIT_SCM_EXEC_FAILURE", "message":"Failure attempting to launch OLE service."},

0x80004012: { "code": "CO_E_INIT_ONLY_SINGLE_THREADED", "message":"There was an attempt to call CoInitialize a second time while single-threaded."},

0x80004013: { "code": "CO_E_CANT_REMOTE", "message":"A Remote activation was necessary but was not allowed."},

0x80004014: { "code": "CO_E_BAD_SERVER_NAME", "message":"A Remote activation was necessary, but the server name provided was invalid."},

0x80004015: { "code": "CO_E_WRONG_SERVER_IDENTITY", "message":"The class is configured to run as a security ID different from the caller."},

0x80004016: { "code": "CO_E_OLE1DDE_DISABLED", "message":"Use of OLE1 services requiring Dynamic Data Exchange (DDE) Windows is disabled."},

0x80004017: { "code": "CO_E_RUNAS_SYNTAX", "message":"A RunAs specification must be <domain name>\<user name> or simply <user name>."},

0x80004018: { "code": "CO_E_CREATEPROCESS_FAILURE", "message":"The server process could not be started. The path name might be incorrect."},

0x80004019: { "code": "CO_E_RUNAS_CREATEPROCESS_FAILURE", "message":"The server process could not be started as the configured identity. The path name might be incorrect or unavailable."},

0x8000401A: { "code": "CO_E_RUNAS_LOGON_FAILURE", "message":"The server process could not be started because the configured identity is incorrect. Check the user name and password."},

0x8000401B: { "code": "CO_E_LAUNCH_PERMSSION_DENIED", "message":"The client is not allowed to launch this server."},

0x8000401C: { "code": "CO_E_START_SERVICE_FAILURE", "message":"The service providing this server could not be started."},

0x8000401D: { "code": "CO_E_REMOTE_COMMUNICATION_FAILURE", "message":"This computer was unable to communicate with the computer providing the server."},

0x8000401E: { "code": "CO_E_SERVER_START_TIMEOUT", "message":"The server did not respond after being launched."},

0x8000401F: { "code": "CO_E_CLSREG_INCONSISTENT", "message":"The registration information for this server is inconsistent or incomplete."},

0x80004020: { "code": "CO_E_IIDREG_INCONSISTENT", "message":"The registration information for this interface is inconsistent or incomplete."},

0x80004021: { "code": "CO_E_NOT_SUPPORTED", "message":"The operation attempted is not supported."},

0x80004022: { "code": "CO_E_RELOAD_DLL", "message":"A DLL must be loaded."},

0x80004023: { "code": "CO_E_MSI_ERROR", "message":"A Microsoft Software Installer error was encountered."},

0x80004024: { "code": "CO_E_ATTEMPT_TO_CREATE_OUTSIDE_CLIENT_CONTEXT", "message":"The specified activation could not occur in the client context as specified."},

0x80004025: { "code": "CO_E_SERVER_PAUSED", "message":"Activations on the server are paused."},

0x80004026: { "code": "CO_E_SERVER_NOT_PAUSED", "message":"Activations on the server are not paused."},

0x80004027: { "code": "CO_E_CLASS_DISABLED", "message":"The component or application containing the component has been disabled."},

0x80004028: { "code": "CO_E_CLRNOTAVAILABLE", "message":"The common language runtime is not available."},

0x80004029: { "code": "CO_E_ASYNC_WORK_REJECTED", "message":"The thread-pool rejected the submitted asynchronous work."},

0x8000402A: { "code": "CO_E_SERVER_INIT_TIMEOUT", "message":"The server started, but it did not finish initializing in a timely fashion."},

0x8000402B: { "code": "CO_E_NO_SECCTX_IN_ACTIVATE", "message":"Unable to complete the call because there is no COM+ security context inside IObjectControl.Activate."},

0x80004030: { "code": "CO_E_TRACKER_CONFIG", "message":"The provided tracker configuration is invalid."},

0x80004031: { "code": "CO_E_THREADPOOL_CONFIG", "message":"The provided thread pool configuration is invalid."},

0x80004032: { "code": "CO_E_SXS_CONFIG", "message":"The provided side-by-side configuration is invalid."},

0x80004033: { "code": "CO_E_MALFORMED_SPN", "message":"The server principal name (SPN) obtained during security negotiation is malformed."},

0x8000FFFF: { "code": "E_UNEXPECTED", "message":"Catastrophic failure."},

0x80010001: { "code": "RPC_E_CALL_REJECTED", "message":"Call was rejected by callee."},

0x80010002: { "code": "RPC_E_CALL_CANCELED", "message":"Call was canceled by the message filter."},

0x80010003: { "code": "RPC_E_CANTPOST_INSENDCALL", "message":"The caller is dispatching an intertask SendMessage call and cannot call out via PostMessage."},

0x80010004: { "code": "RPC_E_CANTCALLOUT_INASYNCCALL", "message":"The caller is dispatching an asynchronous call and cannot make an outgoing call on behalf of this call."},

0x80010005: { "code": "RPC_E_CANTCALLOUT_INEXTERNALCALL", "message":"It is illegal to call out while inside message filter."},

0x80010006: { "code": "RPC_E_CONNECTION_TERMINATED", "message":"The connection terminated or is in a bogus state and can no longer be used. Other connections are still valid."},

0x80010007: { "code": "RPC_E_SERVER_DIED", "message":"The callee (the server, not the server application) is not available and disappeared; all connections are invalid. The call might have executed."},

0x80010008: { "code": "RPC_E_CLIENT_DIED", "message":"The caller (client) disappeared while the callee (server) was processing a call."},

0x80010009: { "code": "RPC_E_INVALID_DATAPACKET", "message":"The data packet with the marshaled parameter data is incorrect."},

0x8001000A: { "code": "RPC_E_CANTTRANSMIT_CALL", "message":"The call was not transmitted properly; the message queue was full and was not emptied after yielding."},

0x8001000B: { "code": "RPC_E_CLIENT_CANTMARSHAL_DATA", "message":"The client RPC caller cannot marshal the parameter data due to errors (such as low memory)."},

0x8001000C: { "code": "RPC_E_CLIENT_CANTUNMARSHAL_DATA", "message":"The client RPC caller cannot unmarshal the return data due to errors (such as low memory)."},

0x8001000D: { "code": "RPC_E_SERVER_CANTMARSHAL_DATA", "message":"The server RPC callee cannot marshal the return data due to errors (such as low memory)."},

0x8001000E: { "code": "RPC_E_SERVER_CANTUNMARSHAL_DATA", "message":"The server RPC callee cannot unmarshal the parameter data due to errors (such as low memory)."},

0x8001000F: { "code": "RPC_E_INVALID_DATA", "message":"Received data is invalid. The data might be server or client data."},

0x80010010: { "code": "RPC_E_INVALID_PARAMETER", "message":"A particular parameter is invalid and cannot be (un)marshaled."},

0x80010011: { "code": "RPC_E_CANTCALLOUT_AGAIN", "message":"There is no second outgoing call on same channel in DDE conversation."},

0x80010012: { "code": "RPC_E_SERVER_DIED_DNE", "message":"The callee (the server, not the server application) is not available and disappeared; all connections are invalid. The call did not execute."},

0x80010100: { "code": "RPC_E_SYS_CALL_FAILED", "message":"System call failed."},

0x80010101: { "code": "RPC_E_OUT_OF_RESOURCES", "message":"Could not allocate some required resource (such as memory or events)"},

0x80010102: { "code": "RPC_E_ATTEMPTED_MULTITHREAD", "message":"Attempted to make calls on more than one thread in single-threaded mode."},

0x80010103: { "code": "RPC_E_NOT_REGISTERED", "message":"The requested interface is not registered on the server object."},

0x80010104: { "code": "RPC_E_FAULT", "message":"RPC could not call the server or could not return the results of calling the server."},

0x80010105: { "code": "RPC_E_SERVERFAULT", "message":"The server threw an exception."},

0x80010106: { "code": "RPC_E_CHANGED_MODE", "message":"Cannot change thread mode after it is set."},

0x80010107: { "code": "RPC_E_INVALIDMETHOD", "message":"The method called does not exist on the server."},

0x80010108: { "code": "RPC_E_DISCONNECTED", "message":"The object invoked has disconnected from its clients."},

0x80010109: { "code": "RPC_E_RETRY", "message":"The object invoked chose not to process the call now. Try again later."},

0x8001010A: { "code": "RPC_E_SERVERCALL_RETRYLATER", "message":"The message filter indicated that the application is busy."},

0x8001010B: { "code": "RPC_E_SERVERCALL_REJECTED", "message":"The message filter rejected the call."},

0x8001010C: { "code": "RPC_E_INVALID_CALLDATA", "message":"A call control interface was called with invalid data."},

0x8001010D: { "code": "RPC_E_CANTCALLOUT_ININPUTSYNCCALL", "message":"An outgoing call cannot be made because the application is dispatching an input-synchronous call."},

0x8001010E: { "code": "RPC_E_WRONG_THREAD", "message":"The application called an interface that was marshaled for a different thread."},

0x8001010F: { "code": "RPC_E_THREAD_NOT_INIT", "message":"CoInitialize has not been called on the current thread."},

0x80010110: { "code": "RPC_E_VERSION_MISMATCH", "message":"The version of OLE on the client and server machines does not match."},

0x80010111: { "code": "RPC_E_INVALID_HEADER", "message":"OLE received a packet with an invalid header."},

0x80010112: { "code": "RPC_E_INVALID_EXTENSION", "message":"OLE received a packet with an invalid extension."},

0x80010113: { "code": "RPC_E_INVALID_IPID", "message":"The requested object or interface does not exist."},

0x80010114: { "code": "RPC_E_INVALID_OBJECT", "message":"The requested object does not exist."},

0x80010115: { "code": "RPC_S_CALLPENDING", "message":"OLE has sent a request and is waiting for a reply."},

0x80010116: { "code": "RPC_S_WAITONTIMER", "message":"OLE is waiting before retrying a request."},

0x80010117: { "code": "RPC_E_CALL_COMPLETE", "message":"Call context cannot be accessed after call completed."},

0x80010118: { "code": "RPC_E_UNSECURE_CALL", "message":"Impersonate on unsecure calls is not supported."},

0x80010119: { "code": "RPC_E_TOO_LATE", "message":"Security must be initialized before any interfaces are marshaled or unmarshaled. It cannot be changed after initialized."},

0x8001011A: { "code": "RPC_E_NO_GOOD_SECURITY_PACKAGES", "message":"No security packages are installed on this machine, the user is not logged on, or there are no compatible security packages between the client and server."},

0x8001011B: { "code": "RPC_E_ACCESS_DENIED", "message":"Access is denied."},

0x8001011C: { "code": "RPC_E_REMOTE_DISABLED", "message":"Remote calls are not allowed for this process."},

0x8001011D: { "code": "RPC_E_INVALID_OBJREF", "message":"The marshaled interface data packet (OBJREF) has an invalid or unknown format."},

0x8001011E: { "code": "RPC_E_NO_CONTEXT", "message":"No context is associated with this call. This happens for some custom marshaled calls and on the client side of the call."},

0x8001011F: { "code": "RPC_E_TIMEOUT", "message":"This operation returned because the time-out period expired."},

0x80010120: { "code": "RPC_E_NO_SYNC", "message":"There are no synchronize objects to wait on."},

0x80010121: { "code": "RPC_E_FULLSIC_REQUIRED", "message":"Full subject issuer chain Secure Sockets Layer (SSL) principal name expected from the server."},

0x80010122: { "code": "RPC_E_INVALID_STD_NAME", "message":"Principal name is not a valid Microsoft standard (msstd) name."},

0x80010123: { "code": "CO_E_FAILEDTOIMPERSONATE", "message":"Unable to impersonate DCOM client."},

0x80010124: { "code": "CO_E_FAILEDTOGETSECCTX", "message":"Unable to obtain server's security context."},

0x80010125: { "code": "CO_E_FAILEDTOOPENTHREADTOKEN", "message":"Unable to open the access token of the current thread."},

0x80010126: { "code": "CO_E_FAILEDTOGETTOKENINFO", "message":"Unable to obtain user information from an access token."},

0x80010127: { "code": "CO_E_TRUSTEEDOESNTMATCHCLIENT", "message":"The client who called IAccessControl::IsAccessPermitted was not the trustee provided to the method."},

0x80010128: { "code": "CO_E_FAILEDTOQUERYCLIENTBLANKET", "message":"Unable to obtain the client's security blanket."},

0x80010129: { "code": "CO_E_FAILEDTOSETDACL", "message":"Unable to set a discretionary access control list (ACL) into a security descriptor."},

0x8001012A: { "code": "CO_E_ACCESSCHECKFAILED", "message":"The system function AccessCheck returned false."},

0x8001012B: { "code": "CO_E_NETACCESSAPIFAILED", "message":"Either NetAccessDel or NetAccessAdd returned an error code."},

0x8001012C: { "code": "CO_E_WRONGTRUSTEENAMESYNTAX", "message":"One of the trustee strings provided by the user did not conform to the <Domain>\<Name> syntax and it was not the *\" string\"."},

0x8001012D: { "code": "CO_E_INVALIDSID", "message":"One of the security identifiers provided by the user was invalid."},

0x8001012E: { "code": "CO_E_CONVERSIONFAILED", "message":"Unable to convert a wide character trustee string to a multiple-byte trustee string."},

0x8001012F: { "code": "CO_E_NOMATCHINGSIDFOUND", "message":"Unable to find a security identifier that corresponds to a trustee string provided by the user."},

0x80010130: { "code": "CO_E_LOOKUPACCSIDFAILED", "message":"The system function LookupAccountSID failed."},

0x80010131: { "code": "CO_E_NOMATCHINGNAMEFOUND", "message":"Unable to find a trustee name that corresponds to a security identifier provided by the user."},

0x80010132: { "code": "CO_E_LOOKUPACCNAMEFAILED", "message":"The system function LookupAccountName failed."},

0x80010133: { "code": "CO_E_SETSERLHNDLFAILED", "message":"Unable to set or reset a serialization handle."},

0x80010134: { "code": "CO_E_FAILEDTOGETWINDIR", "message":"Unable to obtain the Windows directory."},

0x80010135: { "code": "CO_E_PATHTOOLONG", "message":"Path too long."},

0x80010136: { "code": "CO_E_FAILEDTOGENUUID", "message":"Unable to generate a UUID."},

0x80010137: { "code": "CO_E_FAILEDTOCREATEFILE", "message":"Unable to create file."},

0x80010138: { "code": "CO_E_FAILEDTOCLOSEHANDLE", "message":"Unable to close a serialization handle or a file handle."},

0x80010139: { "code": "CO_E_EXCEEDSYSACLLIMIT", "message":"The number of access control entries (ACEs) in an ACL exceeds the system limit."},

0x8001013A: { "code": "CO_E_ACESINWRONGORDER", "message":"Not all the DENY_ACCESS ACEs are arranged in front of the GRANT_ACCESS ACEs in the stream."},

0x8001013B: { "code": "CO_E_INCOMPATIBLESTREAMVERSION", "message":"The version of ACL format in the stream is not supported by this implementation of IAccessControl."},

0x8001013C: { "code": "CO_E_FAILEDTOOPENPROCESSTOKEN", "message":"Unable to open the access token of the server process."},

0x8001013D: { "code": "CO_E_DECODEFAILED", "message":"Unable to decode the ACL in the stream provided by the user."},

0x8001013F: { "code": "CO_E_ACNOTINITIALIZED", "message":"The COM IAccessControl object is not initialized."},

0x80010140: { "code": "CO_E_CANCEL_DISABLED", "message":"Call Cancellation is disabled."},

0x8001FFFF: { "code": "RPC_E_UNEXPECTED", "message":"An internal error occurred."},

0x80020001: { "code": "DISP_E_UNKNOWNINTERFACE", "message":"Unknown interface."},

0x80020003: { "code": "DISP_E_MEMBERNOTFOUND", "message":"Member not found."},

0x80020004: { "code": "DISP_E_PARAMNOTFOUND", "message":"Parameter not found."},

0x80020005: { "code": "DISP_E_TYPEMISMATCH", "message":"Type mismatch."},

0x80020006: { "code": "DISP_E_UNKNOWNNAME", "message":"Unknown name."},

0x80020007: { "code": "DISP_E_NONAMEDARGS", "message":"No named arguments."},

0x80020008: { "code": "DISP_E_BADVARTYPE", "message":"Bad variable type."},

0x80020009: { "code": "DISP_E_EXCEPTION", "message":"Exception occurred."},

0x8002000A: { "code": "DISP_E_OVERFLOW", "message":"Out of present range."},

0x8002000B: { "code": "DISP_E_BADINDEX", "message":"Invalid index."},

0x8002000C: { "code": "DISP_E_UNKNOWNLCID", "message":"Unknown language."},

0x8002000D: { "code": "DISP_E_ARRAYISLOCKED", "message":"Memory is locked."},

0x8002000E: { "code": "DISP_E_BADPARAMCOUNT", "message":"Invalid number of parameters."},

0x8002000F: { "code": "DISP_E_PARAMNOTOPTIONAL", "message":"Parameter not optional."},

0x80020010: { "code": "DISP_E_BADCALLEE", "message":"Invalid callee."},

0x80020011: { "code": "DISP_E_NOTACOLLECTION", "message":"Does not support a collection."},

0x80020012: { "code": "DISP_E_DIVBYZERO", "message":"Division by zero."},

0x80020013: { "code": "DISP_E_BUFFERTOOSMALL", "message":"Buffer too small."},

0x80028016: { "code": "TYPE_E_BUFFERTOOSMALL", "message":"Buffer too small."},

0x80028017: { "code": "TYPE_E_FIELDNOTFOUND", "message":"Field name not defined in the record."},

0x80028018: { "code": "TYPE_E_INVDATAREAD", "message":"Old format or invalid type library."},

0x80028019: { "code": "TYPE_E_UNSUPFORMAT", "message":"Old format or invalid type library."},

0x8002801C: { "code": "TYPE_E_REGISTRYACCESS", "message":"Error accessing the OLE registry."},

0x8002801D: { "code": "TYPE_E_LIBNOTREGISTERED", "message":"Library not registered."},

0x80028027: { "code": "TYPE_E_UNDEFINEDTYPE", "message":"Bound to unknown type."},

0x80028028: { "code": "TYPE_E_QUALIFIEDNAMEDISALLOWED", "message":"Qualified name disallowed."},

0x80028029: { "code": "TYPE_E_INVALIDSTATE", "message":"Invalid forward reference, or reference to uncompiled type."},

0x8002802A: { "code": "TYPE_E_WRONGTYPEKIND", "message":"Type mismatch."},

0x8002802B: { "code": "TYPE_E_ELEMENTNOTFOUND", "message":"Element not found."},

0x8002802C: { "code": "TYPE_E_AMBIGUOUSNAME", "message":"Ambiguous name."},

0x8002802D: { "code": "TYPE_E_NAMECONFLICT", "message":"Name already exists in the library."},

0x8002802E: { "code": "TYPE_E_UNKNOWNLCID", "message":"Unknown language code identifier (LCID)."},

0x8002802F: { "code": "TYPE_E_DLLFUNCTIONNOTFOUND", "message":"Function not defined in specified DLL."},

0x800288BD: { "code": "TYPE_E_BADMODULEKIND", "message":"Wrong module kind for the operation."},

0x800288C5: { "code": "TYPE_E_SIZETOOBIG", "message":"Size cannot exceed 64 KB."},

0x800288C6: { "code": "TYPE_E_DUPLICATEID", "message":"Duplicate ID in inheritance hierarchy."},

0x800288CF: { "code": "TYPE_E_INVALIDID", "message":"Incorrect inheritance depth in standard OLE hmember."},

0x80028CA0: { "code": "TYPE_E_TYPEMISMATCH", "message":"Type mismatch."},

0x80028CA1: { "code": "TYPE_E_OUTOFBOUNDS", "message":"Invalid number of arguments."},

0x80028CA2: { "code": "TYPE_E_IOERROR", "message":"I/O error."},

0x80028CA3: { "code": "TYPE_E_CANTCREATETMPFILE", "message":"Error creating unique .tmp file."},

0x80029C4A: { "code": "TYPE_E_CANTLOADLIBRARY", "message":"Error loading type library or DLL."},

0x80029C83: { "code": "TYPE_E_INCONSISTENTPROPFUNCS", "message":"Inconsistent property functions."},

0x80029C84: { "code": "TYPE_E_CIRCULARTYPE", "message":"Circular dependency between types and modules."},

0x80030001: { "code": "STG_E_INVALIDFUNCTION", "message":"Unable to perform requested operation."},

0x80030002: { "code": "STG_E_FILENOTFOUND", "message":"%1 could not be found."},

0x80030003: { "code": "STG_E_PATHNOTFOUND", "message":"The path %1 could not be found."},

0x80030004: { "code": "STG_E_TOOMANYOPENFILES", "message":"There are insufficient resources to open another file."},

0x80030005: { "code": "STG_E_ACCESSDENIED", "message":"Access denied."},

0x80030006: { "code": "STG_E_INVALIDHANDLE", "message":"Attempted an operation on an invalid object."},

0x80030008: { "code": "STG_E_INSUFFICIENTMEMORY", "message":"There is insufficient memory available to complete operation."},

0x80030009: { "code": "STG_E_INVALIDPOINTER", "message":"Invalid pointer error."},

0x80030012: { "code": "STG_E_NOMOREFILES", "message":"There are no more entries to return."},

0x80030013: { "code": "STG_E_DISKISWRITEPROTECTED", "message":"Disk is write-protected."},

0x80030019: { "code": "STG_E_SEEKERROR", "message":"An error occurred during a seek operation."},

0x8003001D: { "code": "STG_E_WRITEFAULT", "message":"A disk error occurred during a write operation."},

0x8003001E: { "code": "STG_E_READFAULT", "message":"A disk error occurred during a read operation."},

0x80030020: { "code": "STG_E_SHAREVIOLATION", "message":"A share violation has occurred."},

0x80030021: { "code": "STG_E_LOCKVIOLATION", "message":"A lock violation has occurred."},

0x80030050: { "code": "STG_E_FILEALREADYEXISTS", "message":"%1 already exists."},

0x80030057: { "code": "STG_E_INVALIDPARAMETER", "message":"Invalid parameter error."},

0x80030070: { "code": "STG_E_MEDIUMFULL", "message":"There is insufficient disk space to complete operation."},

0x800300F0: { "code": "STG_E_PROPSETMISMATCHED", "message":"Illegal write of non-simple property to simple property set."},

0x800300FA: { "code": "STG_E_ABNORMALAPIEXIT", "message":"An application programming interface (API) call exited abnormally."},

0x800300FB: { "code": "STG_E_INVALIDHEADER", "message":"The file %1 is not a valid compound file."},

0x800300FC: { "code": "STG_E_INVALIDNAME", "message":"The name %1 is not valid."},

0x800300FD: { "code": "STG_E_UNKNOWN", "message":"An unexpected error occurred."},

0x800300FE: { "code": "STG_E_UNIMPLEMENTEDFUNCTION", "message":"That function is not implemented."},

0x800300FF: { "code": "STG_E_INVALIDFLAG", "message":"Invalid flag error."},

0x80030100: { "code": "STG_E_INUSE", "message":"Attempted to use an object that is busy."},

0x80030101: { "code": "STG_E_NOTCURRENT", "message":"The storage has been changed since the last commit."},

0x80030102: { "code": "STG_E_REVERTED", "message":"Attempted to use an object that has ceased to exist."},

0x80030103: { "code": "STG_E_CANTSAVE", "message":"Cannot save."},

0x80030104: { "code": "STG_E_OLDFORMAT", "message":"The compound file %1 was produced with an incompatible version of storage."},

0x80030105: { "code": "STG_E_OLDDLL", "message":"The compound file %1 was produced with a newer version of storage."},

0x80030106: { "code": "STG_E_SHAREREQUIRED", "message":"Share.exe or equivalent is required for operation."},

0x80030107: { "code": "STG_E_NOTFILEBASEDSTORAGE", "message":"Illegal operation called on non-file based storage."},

0x80030108: { "code": "STG_E_EXTANTMARSHALLINGS", "message":"Illegal operation called on object with extant marshalings."},

0x80030109: { "code": "STG_E_DOCFILECORRUPT", "message":"The docfile has been corrupted."},

0x80030110: { "code": "STG_E_BADBASEADDRESS", "message":"OLE32.DLL has been loaded at the wrong address."},

0x80030111: { "code": "STG_E_DOCFILETOOLARGE", "message":"The compound file is too large for the current implementation."},

0x80030112: { "code": "STG_E_NOTSIMPLEFORMAT", "message":"The compound file was not created with the STGM_SIMPLE flag."},

0x80030201: { "code": "STG_E_INCOMPLETE", "message":"The file download was aborted abnormally. The file is incomplete."},

0x80030202: { "code": "STG_E_TERMINATED", "message":"The file download has been terminated."},

0x80030305: { "code": "STG_E_STATUS_COPY_PROTECTION_FAILURE", "message":"Generic Copy Protection Error."},

0x80030306: { "code": "STG_E_CSS_AUTHENTICATION_FAILURE", "message":"Copy Protection Error—DVD CSS Authentication failed."},

0x80030307: { "code": "STG_E_CSS_KEY_NOT_PRESENT", "message":"Copy Protection Error—The given sector does not have a valid CSS key."},

0x80030308: { "code": "STG_E_CSS_KEY_NOT_ESTABLISHED", "message":"Copy Protection Error—DVD session key not established."},

0x80030309: { "code": "STG_E_CSS_SCRAMBLED_SECTOR", "message":"Copy Protection Error—The read failed because the sector is encrypted."},

0x8003030A: { "code": "STG_E_CSS_REGION_MISMATCH", "message":"Copy Protection Error—The current DVD's region does not correspond to the region setting of the drive."},

0x8003030B: { "code": "STG_E_RESETS_EXHAUSTED", "message":"Copy Protection Error—The drive's region setting might be permanent or the number of user resets has been exhausted."},

0x80040000: { "code": "OLE_E_OLEVERB", "message":"Invalid OLEVERB structure."},

0x80040001: { "code": "OLE_E_ADVF", "message":"Invalid advise flags."},

0x80040002: { "code": "OLE_E_ENUM_NOMORE", "message":"Cannot enumerate any more because the associated data is missing."},

0x80040003: { "code": "OLE_E_ADVISENOTSUPPORTED", "message":"This implementation does not take advises."},

0x80040004: { "code": "OLE_E_NOCONNECTION", "message":"There is no connection for this connection ID."},

0x80040005: { "code": "OLE_E_NOTRUNNING", "message":"Need to run the object to perform this operation."},

0x80040006: { "code": "OLE_E_NOCACHE", "message":"There is no cache to operate on."},

0x80040007: { "code": "OLE_E_BLANK", "message":"Uninitialized object."},

0x80040008: { "code": "OLE_E_CLASSDIFF", "message":"Linked object's source class has changed."},

0x80040009: { "code": "OLE_E_CANT_GETMONIKER", "message":"Not able to get the moniker of the object."},

0x8004000A: { "code": "OLE_E_CANT_BINDTOSOURCE", "message":"Not able to bind to the source."},

0x8004000B: { "code": "OLE_E_STATIC", "message":"Object is static; operation not allowed."},

0x8004000C: { "code": "OLE_E_PROMPTSAVECANCELLED", "message":"User canceled out of the Save dialog box."},

0x8004000D: { "code": "OLE_E_INVALIDRECT", "message":"Invalid rectangle."},

0x8004000E: { "code": "OLE_E_WRONGCOMPOBJ", "message":"compobj.dll is too old for the ole2.dll initialized."},

0x8004000F: { "code": "OLE_E_INVALIDHWND", "message":"Invalid window handle."},

0x80040010: { "code": "OLE_E_NOT_INPLACEACTIVE", "message":"Object is not in any of the inplace active states."},

0x80040011: { "code": "OLE_E_CANTCONVERT", "message":"Not able to convert object."},

0x80040012: { "code": "OLE_E_NOSTORAGE", "message":"Not able to perform the operation because object is not given storage yet."},

0x80040064: { "code": "DV_E_FORMATETC", "message":"Invalid FORMATETC structure."},

0x80040065: { "code": "DV_E_DVTARGETDEVICE", "message":"Invalid DVTARGETDEVICE structure."},

0x80040066: { "code": "DV_E_STGMEDIUM", "message":"Invalid STDGMEDIUM structure."},

0x80040067: { "code": "DV_E_STATDATA", "message":"Invalid STATDATA structure."},

0x80040068: { "code": "DV_E_LINDEX", "message":"Invalid lindex."},

0x80040069: { "code": "DV_E_TYMED", "message":"Invalid TYMED structure."},

0x8004006A: { "code": "DV_E_CLIPFORMAT", "message":"Invalid clipboard format."},

0x8004006B: { "code": "DV_E_DVASPECT", "message":"Invalid aspects."},

0x8004006C: { "code": "DV_E_DVTARGETDEVICE_SIZE", "message":"The tdSize parameter of the DVTARGETDEVICE structure is invalid."},

0x8004006D: { "code": "DV_E_NOIVIEWOBJECT", "message":"Object does not support IViewObject interface."},

0x80040100: { "code": "DRAGDROP_E_NOTREGISTERED", "message":"Trying to revoke a drop target that has not been registered."},

0x80040101: { "code": "DRAGDROP_E_ALREADYREGISTERED", "message":"This window has already been registered as a drop target."},

0x80040102: { "code": "DRAGDROP_E_INVALIDHWND", "message":"Invalid window handle."},

0x80040110: { "code": "CLASS_E_NOAGGREGATION", "message":"Class does not support aggregation (or class object is remote)."},

0x80040111: { "code": "CLASS_E_CLASSNOTAVAILABLE", "message":"ClassFactory cannot supply requested class."},

0x80040112: { "code": "CLASS_E_NOTLICENSED", "message":"Class is not licensed for use."},

0x80040140: { "code": "VIEW_E_DRAW", "message":"Error drawing view."},

0x80040150: { "code": "REGDB_E_READREGDB", "message":"Could not read key from registry."},

0x80040151: { "code": "REGDB_E_WRITEREGDB", "message":"Could not write key to registry."},

0x80040152: { "code": "REGDB_E_KEYMISSING", "message":"Could not find the key in the registry."},

0x80040153: { "code": "REGDB_E_INVALIDVALUE", "message":"Invalid value for registry."},

0x80040154: { "code": "REGDB_E_CLASSNOTREG", "message":"Class not registered."},

0x80040155: { "code": "REGDB_E_IIDNOTREG", "message":"Interface not registered."},

0x80040156: { "code": "REGDB_E_BADTHREADINGMODEL", "message":"Threading model entry is not valid."},

0x80040160: { "code": "CAT_E_CATIDNOEXIST", "message":"CATID does not exist."},

0x80040161: { "code": "CAT_E_NODESCRIPTION", "message":"Description not found."},

0x80040164: { "code": "CS_E_PACKAGE_NOTFOUND", "message":"No package in the software installation data in Active Directory meets this criteria."},

0x80040165: { "code": "CS_E_NOT_DELETABLE", "message":"Deleting this will break the referential integrity of the software installation data in Active Directory."},

0x80040166: { "code": "CS_E_CLASS_NOTFOUND", "message":"The CLSID was not found in the software installation data in Active Directory."},

0x80040167: { "code": "CS_E_INVALID_VERSION", "message":"The software installation data in Active Directory is corrupt."},

0x80040168: { "code": "CS_E_NO_CLASSSTORE", "message":"There is no software installation data in Active Directory."},

0x80040169: { "code": "CS_E_OBJECT_NOTFOUND", "message":"There is no software installation data object in Active Directory."},

0x8004016A: { "code": "CS_E_OBJECT_ALREADY_EXISTS", "message":"The software installation data object in Active Directory already exists."},

0x8004016B: { "code": "CS_E_INVALID_PATH", "message":"The path to the software installation data in Active Directory is not correct."},

0x8004016C: { "code": "CS_E_NETWORK_ERROR", "message":"A network error interrupted the operation."},

0x8004016D: { "code": "CS_E_ADMIN_LIMIT_EXCEEDED", "message":"The size of this object exceeds the maximum size set by the administrator."},

0x8004016E: { "code": "CS_E_SCHEMA_MISMATCH", "message":"The schema for the software installation data in Active Directory does not match the required schema."},

0x8004016F: { "code": "CS_E_INTERNAL_ERROR", "message":"An error occurred in the software installation data in Active Directory."},

0x80040170: { "code": "CACHE_E_NOCACHE_UPDATED", "message":"Cache not updated."},

0x80040180: { "code": "OLEOBJ_E_NOVERBS", "message":"No verbs for OLE object."},

0x80040181: { "code": "OLEOBJ_E_INVALIDVERB", "message":"Invalid verb for OLE object."},

0x800401A0: { "code": "INPLACE_E_NOTUNDOABLE", "message":"Undo is not available."},

0x800401A1: { "code": "INPLACE_E_NOTOOLSPACE", "message":"Space for tools is not available."},

0x800401C0: { "code": "CONVERT10_E_OLESTREAM_GET", "message":"OLESTREAM Get method failed."},

0x800401C1: { "code": "CONVERT10_E_OLESTREAM_PUT", "message":"OLESTREAM Put method failed."},

0x800401C2: { "code": "CONVERT10_E_OLESTREAM_FMT", "message":"Contents of the OLESTREAM not in correct format."},

0x800401C3: { "code": "CONVERT10_E_OLESTREAM_BITMAP_TO_DIB", "message":"There was an error in a Windows GDI call while converting the bitmap to a device-independent bitmap (DIB)."},

0x800401C4: { "code": "CONVERT10_E_STG_FMT", "message":"Contents of the IStorage not in correct format."},

0x800401C5: { "code": "CONVERT10_E_STG_NO_STD_STREAM", "message":"Contents of IStorage is missing one of the standard streams."},

0x800401C6: { "code": "CONVERT10_E_STG_DIB_TO_BITMAP", "message":"There was an error in a Windows Graphics Device Interface (GDI) call while converting the DIB to a bitmap."},

0x800401D0: { "code": "CLIPBRD_E_CANT_OPEN", "message":"OpenClipboard failed."},

0x800401D1: { "code": "CLIPBRD_E_CANT_EMPTY", "message":"EmptyClipboard failed."},

0x800401D2: { "code": "CLIPBRD_E_CANT_SET", "message":"SetClipboard failed."},

0x800401D3: { "code": "CLIPBRD_E_BAD_DATA", "message":"Data on clipboard is invalid."},

0x800401D4: { "code": "CLIPBRD_E_CANT_CLOSE", "message":"CloseClipboard failed."},

0x800401E0: { "code": "MK_E_CONNECTMANUALLY", "message":"Moniker needs to be connected manually."},

0x800401E1: { "code": "MK_E_EXCEEDEDDEADLINE", "message":"Operation exceeded deadline."},

0x800401E2: { "code": "MK_E_NEEDGENERIC", "message":"Moniker needs to be generic."},

0x800401E3: { "code": "MK_E_UNAVAILABLE", "message":"Operation unavailable."},

0x800401E4: { "code": "MK_E_SYNTAX", "message":"Invalid syntax."},

0x800401E5: { "code": "MK_E_NOOBJECT", "message":"No object for moniker."},

0x800401E6: { "code": "MK_E_INVALIDEXTENSION", "message":"Bad extension for file."},

0x800401E7: { "code": "MK_E_INTERMEDIATEINTERFACENOTSUPPORTED", "message":"Intermediate operation failed."},

0x800401E8: { "code": "MK_E_NOTBINDABLE", "message":"Moniker is not bindable."},

0x800401E9: { "code": "MK_E_NOTBOUND", "message":"Moniker is not bound."},

0x800401EA: { "code": "MK_E_CANTOPENFILE", "message":"Moniker cannot open file."},

0x800401EB: { "code": "MK_E_MUSTBOTHERUSER", "message":"User input required for operation to succeed."},

0x800401EC: { "code": "MK_E_NOINVERSE", "message":"Moniker class has no inverse."},

0x800401ED: { "code": "MK_E_NOSTORAGE", "message":"Moniker does not refer to storage."},

0x800401EE: { "code": "MK_E_NOPREFIX", "message":"No common prefix."},

0x800401EF: { "code": "MK_E_ENUMERATION_FAILED", "message":"Moniker could not be enumerated."},

0x800401F0: { "code": "CO_E_NOTINITIALIZED", "message":"CoInitialize has not been called."},

0x800401F1: { "code": "CO_E_ALREADYINITIALIZED", "message":"CoInitialize has already been called."},

0x800401F2: { "code": "CO_E_CANTDETERMINECLASS", "message":"Class of object cannot be determined."},

0x800401F3: { "code": "CO_E_CLASSSTRING", "message":"Invalid class string."},

0x800401F4: { "code": "CO_E_IIDSTRING", "message":"Invalid interface string."},

0x800401F5: { "code": "CO_E_APPNOTFOUND", "message":"Application not found."},

0x800401F6: { "code": "CO_E_APPSINGLEUSE", "message":"Application cannot be run more than once."},

0x800401F7: { "code": "CO_E_ERRORINAPP", "message":"Some error in application."},

0x800401F8: { "code": "CO_E_DLLNOTFOUND", "message":"DLL for class not found."},

0x800401F9: { "code": "CO_E_ERRORINDLL", "message":"Error in the DLL."},

0x800401FA: { "code": "CO_E_WRONGOSFORAPP", "message":"Wrong operating system or operating system version for application."},

0x800401FB: { "code": "CO_E_OBJNOTREG", "message":"Object is not registered."},

0x800401FC: { "code": "CO_E_OBJISREG", "message":"Object is already registered."},

0x800401FD: { "code": "CO_E_OBJNOTCONNECTED", "message":"Object is not connected to server."},

0x800401FE: { "code": "CO_E_APPDIDNTREG", "message":"Application was launched, but it did not register a class factory."},

0x800401FF: { "code": "CO_E_RELEASED", "message":"Object has been released."},

0x80040201: { "code": "EVENT_E_ALL_SUBSCRIBERS_FAILED", "message":"An event was unable to invoke any of the subscribers."},

0x80040203: { "code": "EVENT_E_QUERYSYNTAX", "message":"A syntax error occurred trying to evaluate a query string."},

0x80040204: { "code": "EVENT_E_QUERYFIELD", "message":"An invalid field name was used in a query string."},

0x80040205: { "code": "EVENT_E_INTERNALEXCEPTION", "message":"An unexpected exception was raised."},

0x80040206: { "code": "EVENT_E_INTERNALERROR", "message":"An unexpected internal error was detected."},

0x80040207: { "code": "EVENT_E_INVALID_PER_USER_SID", "message":"The owner security identifier (SID) on a per-user subscription does not exist."},

0x80040208: { "code": "EVENT_E_USER_EXCEPTION", "message":"A user-supplied component or subscriber raised an exception."},

0x80040209: { "code": "EVENT_E_TOO_MANY_METHODS", "message":"An interface has too many methods to fire events from."},

0x8004020A: { "code": "EVENT_E_MISSING_EVENTCLASS", "message":"A subscription cannot be stored unless its event class already exists."},

0x8004020B: { "code": "EVENT_E_NOT_ALL_REMOVED", "message":"Not all the objects requested could be removed."},

0x8004020C: { "code": "EVENT_E_COMPLUS_NOT_INSTALLED", "message":"COM+ is required for this operation, but it is not installed."},

0x8004020D: { "code": "EVENT_E_CANT_MODIFY_OR_DELETE_UNCONFIGURED_OBJECT", "message":"Cannot modify or delete an object that was not added using the COM+ Administrative SDK."},

0x8004020E: { "code": "EVENT_E_CANT_MODIFY_OR_DELETE_CONFIGURED_OBJECT", "message":"Cannot modify or delete an object that was added using the COM+ Administrative SDK."},

0x8004020F: { "code": "EVENT_E_INVALID_EVENT_CLASS_PARTITION", "message":"The event class for this subscription is in an invalid partition."},

0x80040210: { "code": "EVENT_E_PER_USER_SID_NOT_LOGGED_ON", "message":"The owner of the PerUser subscription is not logged on to the system specified."},

0x80041309: { "code": "SCHED_E_TRIGGER_NOT_FOUND", "message":"Trigger not found."},

0x8004130A: { "code": "SCHED_E_TASK_NOT_READY", "message":"One or more of the properties that are needed to run this task have not been set."},

0x8004130B: { "code": "SCHED_E_TASK_NOT_RUNNING", "message":"There is no running instance of the task."},

0x8004130C: { "code": "SCHED_E_SERVICE_NOT_INSTALLED", "message":"The Task Scheduler service is not installed on this computer."},

0x8004130D: { "code": "SCHED_E_CANNOT_OPEN_TASK", "message":"The task object could not be opened."},

0x8004130E: { "code": "SCHED_E_INVALID_TASK", "message":"The object is either an invalid task object or is not a task object."},

0x8004130F: { "code": "SCHED_E_ACCOUNT_INFORMATION_NOT_SET", "message":"No account information could be found in the Task Scheduler security database for the task indicated."},

0x80041310: { "code": "SCHED_E_ACCOUNT_NAME_NOT_FOUND", "message":"Unable to establish existence of the account specified."},

0x80041311: { "code": "SCHED_E_ACCOUNT_DBASE_CORRUPT", "message":"Corruption was detected in the Task Scheduler security database; the database has been reset."},

0x80041312: { "code": "SCHED_E_NO_SECURITY_SERVICES", "message":"Task Scheduler security services are available only on Windows NT operating system."},

0x80041313: { "code": "SCHED_E_UNKNOWN_OBJECT_VERSION", "message":"The task object version is either unsupported or invalid."},

0x80041314: { "code": "SCHED_E_UNSUPPORTED_ACCOUNT_OPTION", "message":"The task has been configured with an unsupported combination of account settings and run-time options."},

0x80041315: { "code": "SCHED_E_SERVICE_NOT_RUNNING", "message":"The Task Scheduler service is not running."},

0x80041316: { "code": "SCHED_E_UNEXPECTEDNODE", "message":"The task XML contains an unexpected node."},

0x80041317: { "code": "SCHED_E_NAMESPACE", "message":"The task XML contains an element or attribute from an unexpected namespace."},

0x80041318: { "code": "SCHED_E_INVALIDVALUE", "message":"The task XML contains a value that is incorrectly formatted or out of range."},

0x80041319: { "code": "SCHED_E_MISSINGNODE", "message":"The task XML is missing a required element or attribute."},

0x8004131A: { "code": "SCHED_E_MALFORMEDXML", "message":"The task XML is malformed."},

0x8004131D: { "code": "SCHED_E_TOO_MANY_NODES", "message":"The task XML contains too many nodes of the same type."},

0x8004131E: { "code": "SCHED_E_PAST_END_BOUNDARY", "message":"The task cannot be started after the trigger's end boundary."},

0x8004131F: { "code": "SCHED_E_ALREADY_RUNNING", "message":"An instance of this task is already running."},

0x80041320: { "code": "SCHED_E_USER_NOT_LOGGED_ON", "message":"The task will not run because the user is not logged on."},

0x80041321: { "code": "SCHED_E_INVALID_TASK_HASH", "message":"The task image is corrupt or has been tampered with."},

0x80041322: { "code": "SCHED_E_SERVICE_NOT_AVAILABLE", "message":"The Task Scheduler service is not available."},

0x80041323: { "code": "SCHED_E_SERVICE_TOO_BUSY", "message":"The Task Scheduler service is too busy to handle your request. Try again later."},

0x80041324: { "code": "SCHED_E_TASK_ATTEMPTED", "message":"The Task Scheduler service attempted to run the task, but the task did not run due to one of the constraints in the task definition."},

0x8004D000: { "code": "XACT_E_ALREADYOTHERSINGLEPHASE", "message":"Another single phase resource manager has already been enlisted in this transaction."},

0x8004D001: { "code": "XACT_E_CANTRETAIN", "message":"A retaining commit or abort is not supported."},

0x8004D002: { "code": "XACT_E_COMMITFAILED", "message":"The transaction failed to commit for an unknown reason. The transaction was aborted."},

0x8004D003: { "code": "XACT_E_COMMITPREVENTED", "message":"Cannot call commit on this transaction object because the calling application did not initiate the transaction."},

0x8004D004: { "code": "XACT_E_HEURISTICABORT", "message":"Instead of committing, the resource heuristically aborted."},

0x8004D005: { "code": "XACT_E_HEURISTICCOMMIT", "message":"Instead of aborting, the resource heuristically committed."},

0x8004D006: { "code": "XACT_E_HEURISTICDAMAGE", "message":"Some of the states of the resource were committed while others were aborted, likely because of heuristic decisions."},

0x8004D007: { "code": "XACT_E_HEURISTICDANGER", "message":"Some of the states of the resource might have been committed while others were aborted, likely because of heuristic decisions."},

0x8004D008: { "code": "XACT_E_ISOLATIONLEVEL", "message":"The requested isolation level is not valid or supported."},

0x8004D009: { "code": "XACT_E_NOASYNC", "message":"The transaction manager does not support an asynchronous operation for this method."},

0x8004D00A: { "code": "XACT_E_NOENLIST", "message":"Unable to enlist in the transaction."},

0x8004D00B: { "code": "XACT_E_NOISORETAIN", "message":"The requested semantics of retention of isolation across retaining commit and abort boundaries cannot be supported by this transaction implementation, or isoFlags was not equal to 0."},

0x8004D00C: { "code": "XACT_E_NORESOURCE", "message":"There is no resource presently associated with this enlistment."},

0x8004D00D: { "code": "XACT_E_NOTCURRENT", "message":"The transaction failed to commit due to the failure of optimistic concurrency control in at least one of the resource managers."},

0x8004D00E: { "code": "XACT_E_NOTRANSACTION", "message":"The transaction has already been implicitly or explicitly committed or aborted."},

0x8004D00F: { "code": "XACT_E_NOTSUPPORTED", "message":"An invalid combination of flags was specified."},

0x8004D010: { "code": "XACT_E_UNKNOWNRMGRID", "message":"The resource manager ID is not associated with this transaction or the transaction manager."},

0x8004D011: { "code": "XACT_E_WRONGSTATE", "message":"This method was called in the wrong state."},

0x8004D012: { "code": "XACT_E_WRONGUOW", "message":"The indicated unit of work does not match the unit of work expected by the resource manager."},

0x8004D013: { "code": "XACT_E_XTIONEXISTS", "message":"An enlistment in a transaction already exists."},

0x8004D014: { "code": "XACT_E_NOIMPORTOBJECT", "message":"An import object for the transaction could not be found."},

0x8004D015: { "code": "XACT_E_INVALIDCOOKIE", "message":"The transaction cookie is invalid."},

0x8004D016: { "code": "XACT_E_INDOUBT", "message":"The transaction status is in doubt. A communication failure occurred, or a transaction manager or resource manager has failed."},

0x8004D017: { "code": "XACT_E_NOTIMEOUT", "message":"A time-out was specified, but time-outs are not supported."},

0x8004D018: { "code": "XACT_E_ALREADYINPROGRESS", "message":"The requested operation is already in progress for the transaction."},

0x8004D019: { "code": "XACT_E_ABORTED", "message":"The transaction has already been aborted."},

0x8004D01A: { "code": "XACT_E_LOGFULL", "message":"The Transaction Manager returned a log full error."},

0x8004D01B: { "code": "XACT_E_TMNOTAVAILABLE", "message":"The transaction manager is not available."},

0x8004D01C: { "code": "XACT_E_CONNECTION_DOWN", "message":"A connection with the transaction manager was lost."},

0x8004D01D: { "code": "XACT_E_CONNECTION_DENIED", "message":"A request to establish a connection with the transaction manager was denied."},

0x8004D01E: { "code": "XACT_E_REENLISTTIMEOUT", "message":"Resource manager reenlistment to determine transaction status timed out."},

0x8004D01F: { "code": "XACT_E_TIP_CONNECT_FAILED", "message":"The transaction manager failed to establish a connection with another Transaction Internet Protocol (TIP) transaction manager."},

0x8004D020: { "code": "XACT_E_TIP_PROTOCOL_ERROR", "message":"The transaction manager encountered a protocol error with another TIP transaction manager."},

0x8004D021: { "code": "XACT_E_TIP_PULL_FAILED", "message":"The transaction manager could not propagate a transaction from another TIP transaction manager."},

0x8004D022: { "code": "XACT_E_DEST_TMNOTAVAILABLE", "message":"The transaction manager on the destination machine is not available."},

0x8004D023: { "code": "XACT_E_TIP_DISABLED", "message":"The transaction manager has disabled its support for TIP."},

0x8004D024: { "code": "XACT_E_NETWORK_TX_DISABLED", "message":"The transaction manager has disabled its support for remote or network transactions."},

0x8004D025: { "code": "XACT_E_PARTNER_NETWORK_TX_DISABLED", "message":"The partner transaction manager has disabled its support for remote or network transactions."},

0x8004D026: { "code": "XACT_E_XA_TX_DISABLED", "message":"The transaction manager has disabled its support for XA transactions."},

0x8004D027: { "code": "XACT_E_UNABLE_TO_READ_DTC_CONFIG", "message":"Microsoft Distributed Transaction Coordinator (MSDTC) was unable to read its configuration information."},

0x8004D028: { "code": "XACT_E_UNABLE_TO_LOAD_DTC_PROXY", "message":"MSDTC was unable to load the DTC proxy DLL."},

0x8004D029: { "code": "XACT_E_ABORTING", "message":"The local transaction has aborted."},

0x8004D080: { "code": "XACT_E_CLERKNOTFOUND", "message":"The specified CRM clerk was not found. It might have completed before it could be held."},

0x8004D081: { "code": "XACT_E_CLERKEXISTS", "message":"The specified CRM clerk does not exist."},

0x8004D082: { "code": "XACT_E_RECOVERYINPROGRESS", "message":"Recovery of the CRM log file is still in progress."},

0x8004D083: { "code": "XACT_E_TRANSACTIONCLOSED", "message":"The transaction has completed, and the log records have been discarded from the log file. They are no longer available."},

0x8004D084: { "code": "XACT_E_INVALIDLSN", "message":"lsnToRead is outside of the current limits of the log"},

0x8004D085: { "code": "XACT_E_REPLAYREQUEST", "message":"The COM+ Compensating Resource Manager has records it wishes to replay."},

0x8004D100: { "code": "XACT_E_CONNECTION_REQUEST_DENIED", "message":"The request to connect to the specified transaction coordinator was denied."},

0x8004D101: { "code": "XACT_E_TOOMANY_ENLISTMENTS", "message":"The maximum number of enlistments for the specified transaction has been reached."},

0x8004D102: { "code": "XACT_E_DUPLICATE_GUID", "message":"A resource manager with the same identifier is already registered with the specified transaction coordinator."},

0x8004D103: { "code": "XACT_E_NOTSINGLEPHASE", "message":"The prepare request given was not eligible for single-phase optimizations."},

0x8004D104: { "code": "XACT_E_RECOVERYALREADYDONE", "message":"RecoveryComplete has already been called for the given resource manager."},

0x8004D105: { "code": "XACT_E_PROTOCOL", "message":"The interface call made was incorrect for the current state of the protocol."},

0x8004D106: { "code": "XACT_E_RM_FAILURE", "message":"The xa_open call failed for the XA resource."},

0x8004D107: { "code": "XACT_E_RECOVERY_FAILED", "message":"The xa_recover call failed for the XA resource."},

0x8004D108: { "code": "XACT_E_LU_NOT_FOUND", "message":"The logical unit of work specified cannot be found."},

0x8004D109: { "code": "XACT_E_DUPLICATE_LU", "message":"The specified logical unit of work already exists."},

0x8004D10A: { "code": "XACT_E_LU_NOT_CONNECTED", "message":"Subordinate creation failed. The specified logical unit of work was not connected."},

0x8004D10B: { "code": "XACT_E_DUPLICATE_TRANSID", "message":"A transaction with the given identifier already exists."},

0x8004D10C: { "code": "XACT_E_LU_BUSY", "message":"The resource is in use."},

0x8004D10D: { "code": "XACT_E_LU_NO_RECOVERY_PROCESS", "message":"The LU Recovery process is down."},

0x8004D10E: { "code": "XACT_E_LU_DOWN", "message":"The remote session was lost."},

0x8004D10F: { "code": "XACT_E_LU_RECOVERING", "message":"The resource is currently recovering."},

0x8004D110: { "code": "XACT_E_LU_RECOVERY_MISMATCH", "message":"There was a mismatch in driving recovery."},

0x8004D111: { "code": "XACT_E_RM_UNAVAILABLE", "message":"An error occurred with the XA resource."},

0x8004E002: { "code": "CONTEXT_E_ABORTED", "message":"The root transaction wanted to commit, but the transaction aborted."},

0x8004E003: { "code": "CONTEXT_E_ABORTING", "message":"The COM+ component on which the method call was made has a transaction that has already aborted or is in the process of aborting."},

0x8004E004: { "code": "CONTEXT_E_NOCONTEXT", "message":"There is no Microsoft Transaction Server (MTS) object context."},

0x8004E005: { "code": "CONTEXT_E_WOULD_DEADLOCK", "message":"The component is configured to use synchronization, and this method call would cause a deadlock to occur."},

0x8004E006: { "code": "CONTEXT_E_SYNCH_TIMEOUT", "message":"The component is configured to use synchronization, and a thread has timed out waiting to enter the context."},

0x8004E007: { "code": "CONTEXT_E_OLDREF", "message":"You made a method call on a COM+ component that has a transaction that has already committed or aborted."},

0x8004E00C: { "code": "CONTEXT_E_ROLENOTFOUND", "message":"The specified role was not configured for the application."},

0x8004E00F: { "code": "CONTEXT_E_TMNOTAVAILABLE", "message":"COM+ was unable to talk to the MSDTC."},

0x8004E021: { "code": "CO_E_ACTIVATIONFAILED", "message":"An unexpected error occurred during COM+ activation."},

0x8004E022: { "code": "CO_E_ACTIVATIONFAILED_EVENTLOGGED", "message":"COM+ activation failed. Check the event log for more information."},

0x8004E023: { "code": "CO_E_ACTIVATIONFAILED_CATALOGERROR", "message":"COM+ activation failed due to a catalog or configuration error."},

0x8004E024: { "code": "CO_E_ACTIVATIONFAILED_TIMEOUT", "message":"COM+ activation failed because the activation could not be completed in the specified amount of time."},

0x8004E025: { "code": "CO_E_INITIALIZATIONFAILED", "message":"COM+ activation failed because an initialization function failed. Check the event log for more information."},

0x8004E026: { "code": "CONTEXT_E_NOJIT", "message":"The requested operation requires that just-in-time (JIT) be in the current context, and it is not."},

0x8004E027: { "code": "CONTEXT_E_NOTRANSACTION", "message":"The requested operation requires that the current context have a transaction, and it does not."},

0x8004E028: { "code": "CO_E_THREADINGMODEL_CHANGED", "message":"The components threading model has changed after install into a COM+ application. Re-install component."},

0x8004E029: { "code": "CO_E_NOIISINTRINSICS", "message":"Internet Information Services (IIS) intrinsics not available. Start your work with IIS."},

0x8004E02A: { "code": "CO_E_NOCOOKIES", "message":"An attempt to write a cookie failed."},

0x8004E02B: { "code": "CO_E_DBERROR", "message":"An attempt to use a database generated a database-specific error."},

0x8004E02C: { "code": "CO_E_NOTPOOLED", "message":"The COM+ component you created must use object pooling to work."},

0x8004E02D: { "code": "CO_E_NOTCONSTRUCTED", "message":"The COM+ component you created must use object construction to work correctly."},

0x8004E02E: { "code": "CO_E_NOSYNCHRONIZATION", "message":"The COM+ component requires synchronization, and it is not configured for it."},

0x8004E02F: { "code": "CO_E_ISOLEVELMISMATCH", "message":"The TxIsolation Level property for the COM+ component being created is stronger than the TxIsolationLevel for the root."},

0x8004E030: { "code": "CO_E_CALL_OUT_OF_TX_SCOPE_NOT_ALLOWED", "message":"The component attempted to make a cross-context call between invocations of EnterTransactionScope and ExitTransactionScope. This is not allowed. Cross-context calls cannot be made while inside a transaction scope."},

0x8004E031: { "code": "CO_E_EXIT_TRANSACTION_SCOPE_NOT_CALLED", "message":"The component made a call to EnterTransactionScope, but did not make a corresponding call to ExitTransactionScope before returning."},

0x80070005: { "code": "E_ACCESSDENIED", "message":"General access denied error."},

0x8007000E: { "code": "E_OUTOFMEMORY", "message":"The server does not have enough memory for the new channel."},

0x80070032: { "code": "ERROR_NOT_SUPPORTED", "message":"The server cannot support a client request for a dynamic virtual channel."},

0x80070057: { "code": "E_INVALIDARG", "message":"One or more arguments are invalid."},

0x80070070: { "code": "ERROR_DISK_FULL", "message":"There is not enough space on the disk."},

0x80080001: { "code": "CO_E_CLASS_CREATE_FAILED", "message":"Attempt to create a class object failed."},

0x80080002: { "code": "CO_E_SCM_ERROR", "message":"OLE service could not bind object."},

0x80080003: { "code": "CO_E_SCM_RPC_FAILURE", "message":"RPC communication failed with OLE service."},

0x80080004: { "code": "CO_E_BAD_PATH", "message":"Bad path to object."},

0x80080005: { "code": "CO_E_SERVER_EXEC_FAILURE", "message":"Server execution failed."},

0x80080006: { "code": "CO_E_OBJSRV_RPC_FAILURE", "message":"OLE service could not communicate with the object server."},

0x80080007: { "code": "MK_E_NO_NORMALIZED", "message":"Moniker path could not be normalized."},

0x80080008: { "code": "CO_E_SERVER_STOPPING", "message":"Object server is stopping when OLE service contacts it."},

0x80080009: { "code": "MEM_E_INVALID_ROOT", "message":"An invalid root block pointer was specified."},

0x80080010: { "code": "MEM_E_INVALID_LINK", "message":"An allocation chain contained an invalid link pointer."},

0x80080011: { "code": "MEM_E_INVALID_SIZE", "message":"The requested allocation size was too large."},

0x80080015: { "code": "CO_E_MISSING_DISPLAYNAME", "message":"The activation requires a display name to be present under the class identifier (CLSID) key."},

0x80080016: { "code": "CO_E_RUNAS_VALUE_MUST_BE_AAA", "message":"The activation requires that the RunAs value for the application is Activate As Activator."},

0x80080017: { "code": "CO_E_ELEVATION_DISABLED", "message":"The class is not configured to support elevated activation."},

0x80090001: { "code": "NTE_BAD_UID", "message":"Bad UID."},

0x80090002: { "code": "NTE_BAD_HASH", "message":"Bad hash."},

0x80090003: { "code": "NTE_BAD_KEY", "message":"Bad key."},

0x80090004: { "code": "NTE_BAD_LEN", "message":"Bad length."},

0x80090005: { "code": "NTE_BAD_DATA", "message":"Bad data."},

0x80090006: { "code": "NTE_BAD_SIGNATURE", "message":"Invalid signature."},

0x80090007: { "code": "NTE_BAD_VER", "message":"Bad version of provider."},

0x80090008: { "code": "NTE_BAD_ALGID", "message":"Invalid algorithm specified."},

0x80090009: { "code": "NTE_BAD_FLAGS", "message":"Invalid flags specified."},

0x8009000A: { "code": "NTE_BAD_TYPE", "message":"Invalid type specified."},

0x8009000B: { "code": "NTE_BAD_KEY_STATE", "message":"Key not valid for use in specified state."},

0x8009000C: { "code": "NTE_BAD_HASH_STATE", "message":"Hash not valid for use in specified state."},

0x8009000D: { "code": "NTE_NO_KEY", "message":"Key does not exist."},

0x8009000E: { "code": "NTE_NO_MEMORY", "message":"Insufficient memory available for the operation."},

0x8009000F: { "code": "NTE_EXISTS", "message":"Object already exists."},

0x80090010: { "code": "NTE_PERM", "message":"Access denied."},

0x80090011: { "code": "NTE_NOT_FOUND", "message":"Object was not found."},

0x80090012: { "code": "NTE_DOUBLE_ENCRYPT", "message":"Data already encrypted."},

0x80090013: { "code": "NTE_BAD_PROVIDER", "message":"Invalid provider specified."},

0x80090014: { "code": "NTE_BAD_PROV_TYPE", "message":"Invalid provider type specified."},

0x80090015: { "code": "NTE_BAD_PUBLIC_KEY", "message":"Provider's public key is invalid."},

0x80090016: { "code": "NTE_BAD_KEYSET", "message":"Key set does not exist."},

0x80090017: { "code": "NTE_PROV_TYPE_NOT_DEF", "message":"Provider type not defined."},

0x80090018: { "code": "NTE_PROV_TYPE_ENTRY_BAD", "message":"The provider type, as registered, is invalid."},

0x80090019: { "code": "NTE_KEYSET_NOT_DEF", "message":"The key set is not defined."},

0x8009001A: { "code": "NTE_KEYSET_ENTRY_BAD", "message":"The key set, as registered, is invalid."},

0x8009001B: { "code": "NTE_PROV_TYPE_NO_MATCH", "message":"Provider type does not match registered value."},

0x8009001C: { "code": "NTE_SIGNATURE_FILE_BAD", "message":"The digital signature file is corrupt."},

0x8009001D: { "code": "NTE_PROVIDER_DLL_FAIL", "message":"Provider DLL failed to initialize correctly."},

0x8009001E: { "code": "NTE_PROV_DLL_NOT_FOUND", "message":"Provider DLL could not be found."},

0x8009001F: { "code": "NTE_BAD_KEYSET_PARAM", "message":"The keyset parameter is invalid."},

0x80090020: { "code": "NTE_FAIL", "message":"An internal error occurred."},

0x80090021: { "code": "NTE_SYS_ERR", "message":"A base error occurred."},

0x80090022: { "code": "NTE_SILENT_CONTEXT", "message":"Provider could not perform the action because the context was acquired as silent."},

0x80090023: { "code": "NTE_TOKEN_KEYSET_STORAGE_FULL", "message":"The security token does not have storage space available for an additional container."},

0x80090024: { "code": "NTE_TEMPORARY_PROFILE", "message":"The profile for the user is a temporary profile."},

0x80090025: { "code": "NTE_FIXEDPARAMETER", "message":"The key parameters could not be set because the configuration service provider (CSP) uses fixed parameters."},

0x80090026: { "code": "NTE_INVALID_HANDLE", "message":"The supplied handle is invalid."},

0x80090027: { "code": "NTE_INVALID_PARAMETER", "message":"The parameter is incorrect."},

0x80090028: { "code": "NTE_BUFFER_TOO_SMALL", "message":"The buffer supplied to a function was too small."},

0x80090029: { "code": "NTE_NOT_SUPPORTED", "message":"The requested operation is not supported."},

0x8009002A: { "code": "NTE_NO_MORE_ITEMS", "message":"No more data is available."},

0x8009002B: { "code": "NTE_BUFFERS_OVERLAP", "message":"The supplied buffers overlap incorrectly."},

0x8009002C: { "code": "NTE_DECRYPTION_FAILURE", "message":"The specified data could not be decrypted."},

0x8009002D: { "code": "NTE_INTERNAL_ERROR", "message":"An internal consistency check failed."},

0x8009002E: { "code": "NTE_UI_REQUIRED", "message":"This operation requires input from the user."},

0x8009002F: { "code": "NTE_HMAC_NOT_SUPPORTED", "message":"The cryptographic provider does not support Hash Message Authentication Code (HMAC)."},

0x80090300: { "code": "SEC_E_INSUFFICIENT_MEMORY", "message":"Not enough memory is available to complete this request."},

0x80090301: { "code": "SEC_E_INVALID_HANDLE", "message":"The handle specified is invalid."},

0x80090302: { "code": "SEC_E_UNSUPPORTED_FUNCTION", "message":"The function requested is not supported."},

0x80090303: { "code": "SEC_E_TARGET_UNKNOWN", "message":"The specified target is unknown or unreachable."},

0x80090304: { "code": "SEC_E_INTERNAL_ERROR", "message":"The Local Security Authority (LSA) cannot be contacted."},

0x80090305: { "code": "SEC_E_SECPKG_NOT_FOUND", "message":"The requested security package does not exist."},

0x80090306: { "code": "SEC_E_NOT_OWNER", "message":"The caller is not the owner of the desired credentials."},

0x80090307: { "code": "SEC_E_CANNOT_INSTALL", "message":"The security package failed to initialize and cannot be installed."},

0x80090308: { "code": "SEC_E_INVALID_TOKEN", "message":"The token supplied to the function is invalid."},

0x80090309: { "code": "SEC_E_CANNOT_PACK", "message":"The security package is not able to marshal the logon buffer, so the logon attempt has failed."},

0x8009030A: { "code": "SEC_E_QOP_NOT_SUPPORTED", "message":"The per-message quality of protection is not supported by the security package."},

0x8009030B: { "code": "SEC_E_NO_IMPERSONATION", "message":"The security context does not allow impersonation of the client."},

0x8009030C: { "code": "SEC_E_LOGON_DENIED", "message":"The logon attempt failed."},

0x8009030D: { "code": "SEC_E_UNKNOWN_CREDENTIALS", "message":"The credentials supplied to the package were not recognized."},

0x8009030E: { "code": "SEC_E_NO_CREDENTIALS", "message":"No credentials are available in the security package."},

0x8009030F: { "code": "SEC_E_MESSAGE_ALTERED", "message":"The message or signature supplied for verification has been altered."},

0x80090310: { "code": "SEC_E_OUT_OF_SEQUENCE", "message":"The message supplied for verification is out of sequence."},

0x80090311: { "code": "SEC_E_NO_AUTHENTICATING_AUTHORITY", "message":"No authority could be contacted for authentication."},

0x80090316: { "code": "SEC_E_BAD_PKGID", "message":"The requested security package does not exist."},

0x80090317: { "code": "SEC_E_CONTEXT_EXPIRED", "message":"The context has expired and can no longer be used."},

0x80090318: { "code": "SEC_E_INCOMPLETE_MESSAGE", "message":"The supplied message is incomplete. The signature was not verified."},

0x80090320: { "code": "SEC_E_INCOMPLETE_CREDENTIALS", "message":"The credentials supplied were not complete and could not be verified. The context could not be initialized."},

0x80090321: { "code": "SEC_E_BUFFER_TOO_SMALL", "message":"The buffers supplied to a function was too small."},

0x80090322: { "code": "SEC_E_WRONG_PRINCIPAL", "message":"The target principal name is incorrect."},

0x80090324: { "code": "SEC_E_TIME_SKEW", "message":"The clocks on the client and server machines are skewed."},

0x80090325: { "code": "SEC_E_UNTRUSTED_ROOT", "message":"The certificate chain was issued by an authority that is not trusted."},

0x80090326: { "code": "SEC_E_ILLEGAL_MESSAGE", "message":"The message received was unexpected or badly formatted."},

0x80090327: { "code": "SEC_E_CERT_UNKNOWN", "message":"An unknown error occurred while processing the certificate."},

0x80090328: { "code": "SEC_E_CERT_EXPIRED", "message":"The received certificate has expired."},

0x80090329: { "code": "SEC_E_ENCRYPT_FAILURE", "message":"The specified data could not be encrypted."},

0x80090330: { "code": "SEC_E_DECRYPT_FAILURE", "message":"The specified data could not be decrypted."},

0x80090331: { "code": "SEC_E_ALGORITHM_MISMATCH", "message":"The client and server cannot communicate because they do not possess a common algorithm."},

0x80090332: { "code": "SEC_E_SECURITY_QOS_FAILED", "message":"The security context could not be established due to a failure in the requested quality of service (for example, mutual authentication or delegation)."},

0x80090333: { "code": "SEC_E_UNFINISHED_CONTEXT_DELETED", "message":"A security context was deleted before the context was completed. This is considered a logon failure."},

0x80090334: { "code": "SEC_E_NO_TGT_REPLY", "message":"The client is trying to negotiate a context and the server requires user-to-user but did not send a ticket granting ticket (TGT) reply."},

0x80090335: { "code": "SEC_E_NO_IP_ADDRESSES", "message":"Unable to accomplish the requested task because the local machine does not have an IP addresses."},

0x80090336: { "code": "SEC_E_WRONG_CREDENTIAL_HANDLE", "message":"The supplied credential handle does not match the credential associated with the security context."},

0x80090337: { "code": "SEC_E_CRYPTO_SYSTEM_INVALID", "message":"The cryptographic system or checksum function is invalid because a required function is unavailable."},

0x80090338: { "code": "SEC_E_MAX_REFERRALS_EXCEEDED", "message":"The number of maximum ticket referrals has been exceeded."},

0x80090339: { "code": "SEC_E_MUST_BE_KDC", "message":"The local machine must be a Kerberos domain controller (KDC), and it is not."},

0x8009033A: { "code": "SEC_E_STRONG_CRYPTO_NOT_SUPPORTED", "message":"The other end of the security negotiation requires strong cryptographics, but it is not supported on the local machine."},

0x8009033B: { "code": "SEC_E_TOO_MANY_PRINCIPALS", "message":"The KDC reply contained more than one principal name."},

0x8009033C: { "code": "SEC_E_NO_PA_DATA", "message":"Expected to find PA data for a hint of what etype to use, but it was not found."},

0x8009033D: { "code": "SEC_E_PKINIT_NAME_MISMATCH", "message":"The client certificate does not contain a valid user principal name (UPN), or does not match the client name in the logon request. Contact your administrator."},

0x8009033E: { "code": "SEC_E_SMARTCARD_LOGON_REQUIRED", "message":"Smart card logon is required and was not used."},

0x8009033F: { "code": "SEC_E_SHUTDOWN_IN_PROGRESS", "message":"A system shutdown is in progress."},

0x80090340: { "code": "SEC_E_KDC_INVALID_REQUEST", "message":"An invalid request was sent to the KDC."},

0x80090341: { "code": "SEC_E_KDC_UNABLE_TO_REFER", "message":"The KDC was unable to generate a referral for the service requested."},

0x80090342: { "code": "SEC_E_KDC_UNKNOWN_ETYPE", "message":"The encryption type requested is not supported by the KDC."},

0x80090343: { "code": "SEC_E_UNSUPPORTED_PREAUTH", "message":"An unsupported pre-authentication mechanism was presented to the Kerberos package."},

0x80090345: { "code": "SEC_E_DELEGATION_REQUIRED", "message":"The requested operation cannot be completed. The computer must be trusted for delegation, and the current user account must be configured to allow delegation."},

0x80090346: { "code": "SEC_E_BAD_BINDINGS", "message":"Client's supplied Security Support Provider Interface (SSPI) channel bindings were incorrect."},

0x80090347: { "code": "SEC_E_MULTIPLE_ACCOUNTS", "message":"The received certificate was mapped to multiple accounts."},

0x80090348: { "code": "SEC_E_NO_KERB_KEY", "message":"No Kerberos key was found."},

0x80090349: { "code": "SEC_E_CERT_WRONG_USAGE", "message":"The certificate is not valid for the requested usage."},

0x80090350: { "code": "SEC_E_DOWNGRADE_DETECTED", "message":"The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you."},

0x80090351: { "code": "SEC_E_SMARTCARD_CERT_REVOKED", "message":"The smart card certificate used for authentication has been revoked. Contact your system administrator. The event log might contain additional information."},

0x80090352: { "code": "SEC_E_ISSUING_CA_UNTRUSTED", "message":"An untrusted certification authority (CA) was detected while processing the smart card certificate used for authentication. Contact your system administrator."},

0x80090353: { "code": "SEC_E_REVOCATION_OFFLINE_C", "message":"The revocation status of the smart card certificate used for authentication could not be determined. Contact your system administrator."},

0x80090354: { "code": "SEC_E_PKINIT_CLIENT_FAILURE", "message":"The smart card certificate used for authentication was not trusted. Contact your system administrator."},

0x80090355: { "code": "SEC_E_SMARTCARD_CERT_EXPIRED", "message":"The smart card certificate used for authentication has expired. Contact your system administrator."},

0x80090356: { "code": "SEC_E_NO_S4U_PROT_SUPPORT", "message":"The Kerberos subsystem encountered an error. A service for user protocol requests was made against a domain controller that does not support services for users."},

0x80090357: { "code": "SEC_E_CROSSREALM_DELEGATION_FAILURE", "message":"An attempt was made by this server to make a Kerberos-constrained delegation request for a target outside the server's realm. This is not supported and indicates a misconfiguration on this server's allowed-to-delegate-to list. Contact your administrator."},

0x80090358: { "code": "SEC_E_REVOCATION_OFFLINE_KDC", "message":"The revocation status of the domain controller certificate used for smart card authentication could not be determined. The system event log contains additional information. Contact your system administrator."},

0x80090359: { "code": "SEC_E_ISSUING_CA_UNTRUSTED_KDC", "message":"An untrusted CA was detected while processing the domain controller certificate used for authentication. The system event log contains additional information. Contact your system administrator."},

0x8009035A: { "code": "SEC_E_KDC_CERT_EXPIRED", "message":"The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log."},

0x8009035B: { "code": "SEC_E_KDC_CERT_REVOKED", "message":"The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log."},

0x8009035D: { "code": "SEC_E_INVALID_PARAMETER", "message":"One or more of the parameters passed to the function were invalid."},

0x8009035E: { "code": "SEC_E_DELEGATION_POLICY", "message":"The client policy does not allow credential delegation to the target server."},

0x8009035F: { "code": "SEC_E_POLICY_NLTM_ONLY", "message":"The client policy does not allow credential delegation to the target server with NLTM only authentication."},

0x80091001: { "code": "CRYPT_E_MSG_ERROR", "message":"An error occurred while performing an operation on a cryptographic message."},

0x80091002: { "code": "CRYPT_E_UNKNOWN_ALGO", "message":"Unknown cryptographic algorithm."},

0x80091003: { "code": "CRYPT_E_OID_FORMAT", "message":"The object identifier is poorly formatted."},

0x80091004: { "code": "CRYPT_E_INVALID_MSG_TYPE", "message":"Invalid cryptographic message type."},

0x80091005: { "code": "CRYPT_E_UNEXPECTED_ENCODING", "message":"Unexpected cryptographic message encoding."},

0x80091006: { "code": "CRYPT_E_AUTH_ATTR_MISSING", "message":"The cryptographic message does not contain an expected authenticated attribute."},

0x80091007: { "code": "CRYPT_E_HASH_VALUE", "message":"The hash value is not correct."},

0x80091008: { "code": "CRYPT_E_INVALID_INDEX", "message":"The index value is not valid."},

0x80091009: { "code": "CRYPT_E_ALREADY_DECRYPTED", "message":"The content of the cryptographic message has already been decrypted."},

0x8009100A: { "code": "CRYPT_E_NOT_DECRYPTED", "message":"The content of the cryptographic message has not been decrypted yet."},

0x8009100B: { "code": "CRYPT_E_RECIPIENT_NOT_FOUND", "message":"The enveloped-data message does not contain the specified recipient."},

0x8009100C: { "code": "CRYPT_E_CONTROL_TYPE", "message":"Invalid control type."},

0x8009100D: { "code": "CRYPT_E_ISSUER_SERIALNUMBER", "message":"Invalid issuer or serial number."},

0x8009100E: { "code": "CRYPT_E_SIGNER_NOT_FOUND", "message":"Cannot find the original signer."},

0x8009100F: { "code": "CRYPT_E_ATTRIBUTES_MISSING", "message":"The cryptographic message does not contain all of the requested attributes."},

0x80091010: { "code": "CRYPT_E_STREAM_MSG_NOT_READY", "message":"The streamed cryptographic message is not ready to return data."},

0x80091011: { "code": "CRYPT_E_STREAM_INSUFFICIENT_DATA", "message":"The streamed cryptographic message requires more data to complete the decode operation."},

0x80092001: { "code": "CRYPT_E_BAD_LEN", "message":"The length specified for the output data was insufficient."},

0x80092002: { "code": "CRYPT_E_BAD_ENCODE", "message":"An error occurred during the encode or decode operation."},

0x80092003: { "code": "CRYPT_E_FILE_ERROR", "message":"An error occurred while reading or writing to a file."},

0x80092004: { "code": "CRYPT_E_NOT_FOUND", "message":"Cannot find object or property."},

0x80092005: { "code": "CRYPT_E_EXISTS", "message":"The object or property already exists."},

0x80092006: { "code": "CRYPT_E_NO_PROVIDER", "message":"No provider was specified for the store or object."},

0x80092007: { "code": "CRYPT_E_SELF_SIGNED", "message":"The specified certificate is self-signed."},

0x80092008: { "code": "CRYPT_E_DELETED_PREV", "message":"The previous certificate or certificate revocation list (CRL) context was deleted."},

0x80092009: { "code": "CRYPT_E_NO_MATCH", "message":"Cannot find the requested object."},

0x8009200A: { "code": "CRYPT_E_UNEXPECTED_MSG_TYPE", "message":"The certificate does not have a property that references a private key."},

0x8009200B: { "code": "CRYPT_E_NO_KEY_PROPERTY", "message":"Cannot find the certificate and private key for decryption."},

0x8009200C: { "code": "CRYPT_E_NO_DECRYPT_CERT", "message":"Cannot find the certificate and private key to use for decryption."},

0x8009200D: { "code": "CRYPT_E_BAD_MSG", "message":"Not a cryptographic message or the cryptographic message is not formatted correctly."},

0x8009200E: { "code": "CRYPT_E_NO_SIGNER", "message":"The signed cryptographic message does not have a signer for the specified signer index."},

0x8009200F: { "code": "CRYPT_E_PENDING_CLOSE", "message":"Final closure is pending until additional frees or closes."},

0x80092010: { "code": "CRYPT_E_REVOKED", "message":"The certificate is revoked."},

0x80092011: { "code": "CRYPT_E_NO_REVOCATION_DLL", "message":"No DLL or exported function was found to verify revocation."},

0x80092012: { "code": "CRYPT_E_NO_REVOCATION_CHECK", "message":"The revocation function was unable to check revocation for the certificate."},

0x80092013: { "code": "CRYPT_E_REVOCATION_OFFLINE", "message":"The revocation function was unable to check revocation because the revocation server was offline."},

0x80092014: { "code": "CRYPT_E_NOT_IN_REVOCATION_DATABASE", "message":"The certificate is not in the revocation server's database."},

0x80092020: { "code": "CRYPT_E_INVALID_NUMERIC_STRING", "message":"The string contains a non-numeric character."},

0x80092021: { "code": "CRYPT_E_INVALID_PRINTABLE_STRING", "message":"The string contains a nonprintable character."},

0x80092022: { "code": "CRYPT_E_INVALID_IA5_STRING", "message":"The string contains a character not in the 7-bit ASCII character set."},

0x80092023: { "code": "CRYPT_E_INVALID_X500_STRING", "message":"The string contains an invalid X500 name attribute key, object identifier (OID), value, or delimiter."},

0x80092024: { "code": "CRYPT_E_NOT_CHAR_STRING", "message":"The dwValueType for the CERT_NAME_VALUE is not one of the character strings. Most likely it is either a CERT_RDN_ENCODED_BLOB or CERT_TDN_OCTED_STRING."},

0x80092025: { "code": "CRYPT_E_FILERESIZED", "message":"The Put operation cannot continue. The file needs to be resized. However, there is already a signature present. A complete signing operation must be done."},

0x80092026: { "code": "CRYPT_E_SECURITY_SETTINGS", "message":"The cryptographic operation failed due to a local security option setting."},

0x80092027: { "code": "CRYPT_E_NO_VERIFY_USAGE_DLL", "message":"No DLL or exported function was found to verify subject usage."},

0x80092028: { "code": "CRYPT_E_NO_VERIFY_USAGE_CHECK", "message":"The called function was unable to perform a usage check on the subject."},

0x80092029: { "code": "CRYPT_E_VERIFY_USAGE_OFFLINE", "message":"The called function was unable to complete the usage check because the server was offline."},

0x8009202A: { "code": "CRYPT_E_NOT_IN_CTL", "message":"The subject was not found in a certificate trust list (CTL)."},

0x8009202B: { "code": "CRYPT_E_NO_TRUSTED_SIGNER", "message":"None of the signers of the cryptographic message or certificate trust list is trusted."},

0x8009202C: { "code": "CRYPT_E_MISSING_PUBKEY_PARA", "message":"The public key's algorithm parameters are missing."},

0x80093000: { "code": "CRYPT_E_OSS_ERROR", "message":"OSS Certificate encode/decode error code base."},

0x80093001: { "code": "OSS_MORE_BUF", "message":"OSS ASN.1 Error: Output Buffer is too small."},

0x80093002: { "code": "OSS_NEGATIVE_UINTEGER", "message":"OSS ASN.1 Error: Signed integer is encoded as a unsigned integer."},

0x80093003: { "code": "OSS_PDU_RANGE", "message":"OSS ASN.1 Error: Unknown ASN.1 data type."},

0x80093004: { "code": "OSS_MORE_INPUT", "message":"OSS ASN.1 Error: Output buffer is too small; the decoded data has been truncated."},

0x80093005: { "code": "OSS_DATA_ERROR", "message":"OSS ASN.1 Error: Invalid data."},

0x80093006: { "code": "OSS_BAD_ARG", "message":"OSS ASN.1 Error: Invalid argument."},

0x80093007: { "code": "OSS_BAD_VERSION", "message":"OSS ASN.1 Error: Encode/Decode version mismatch."},

0x80093008: { "code": "OSS_OUT_MEMORY", "message":"OSS ASN.1 Error: Out of memory."},

0x80093009: { "code": "OSS_PDU_MISMATCH", "message":"OSS ASN.1 Error: Encode/Decode error."},

0x8009300A: { "code": "OSS_LIMITED", "message":"OSS ASN.1 Error: Internal error."},

0x8009300B: { "code": "OSS_BAD_PTR", "message":"OSS ASN.1 Error: Invalid data."},

0x8009300C: { "code": "OSS_BAD_TIME", "message":"OSS ASN.1 Error: Invalid data."},

0x8009300D: { "code": "OSS_INDEFINITE_NOT_SUPPORTED", "message":"OSS ASN.1 Error: Unsupported BER indefinite-length encoding."},

0x8009300E: { "code": "OSS_MEM_ERROR", "message":"OSS ASN.1 Error: Access violation."},

0x8009300F: { "code": "OSS_BAD_TABLE", "message":"OSS ASN.1 Error: Invalid data."},

0x80093010: { "code": "OSS_TOO_LONG", "message":"OSS ASN.1 Error: Invalid data."},

0x80093011: { "code": "OSS_CONSTRAINT_VIOLATED", "message":"OSS ASN.1 Error: Invalid data."},

0x80093012: { "code": "OSS_FATAL_ERROR", "message":"OSS ASN.1 Error: Internal error."},

0x80093013: { "code": "OSS_ACCESS_SERIALIZATION_ERROR", "message":"OSS ASN.1 Error: Multithreading conflict."},

0x80093014: { "code": "OSS_NULL_TBL", "message":"OSS ASN.1 Error: Invalid data."},

0x80093015: { "code": "OSS_NULL_FCN", "message":"OSS ASN.1 Error: Invalid data."},

0x80093016: { "code": "OSS_BAD_ENCRULES", "message":"OSS ASN.1 Error: Invalid data."},

0x80093017: { "code": "OSS_UNAVAIL_ENCRULES", "message":"OSS ASN.1 Error: Encode/Decode function not implemented."},

0x80093018: { "code": "OSS_CANT_OPEN_TRACE_WINDOW", "message":"OSS ASN.1 Error: Trace file error."},

0x80093019: { "code": "OSS_UNIMPLEMENTED", "message":"OSS ASN.1 Error: Function not implemented."},

0x8009301A: { "code": "OSS_OID_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x8009301B: { "code": "OSS_CANT_OPEN_TRACE_FILE", "message":"OSS ASN.1 Error: Trace file error."},

0x8009301C: { "code": "OSS_TRACE_FILE_ALREADY_OPEN", "message":"OSS ASN.1 Error: Trace file error."},

0x8009301D: { "code": "OSS_TABLE_MISMATCH", "message":"OSS ASN.1 Error: Invalid data."},

0x8009301E: { "code": "OSS_TYPE_NOT_SUPPORTED", "message":"OSS ASN.1 Error: Invalid data."},

0x8009301F: { "code": "OSS_REAL_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093020: { "code": "OSS_REAL_CODE_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093021: { "code": "OSS_OUT_OF_RANGE", "message":"OSS ASN.1 Error: Program link error."},

0x80093022: { "code": "OSS_COPIER_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093023: { "code": "OSS_CONSTRAINT_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093024: { "code": "OSS_COMPARATOR_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093025: { "code": "OSS_COMPARATOR_CODE_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093026: { "code": "OSS_MEM_MGR_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093027: { "code": "OSS_PDV_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093028: { "code": "OSS_PDV_CODE_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x80093029: { "code": "OSS_API_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x8009302A: { "code": "OSS_BERDER_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x8009302B: { "code": "OSS_PER_DLL_NOT_LINKED", "message":"OSS ASN.1 Error: Program link error."},

0x8009302C: { "code": "OSS_OPEN_TYPE_ERROR", "message":"OSS ASN.1 Error: Program link error."},

0x8009302D: { "code": "OSS_MUTEX_NOT_CREATED", "message":"OSS ASN.1 Error: System resource error."},

0x8009302E: { "code": "OSS_CANT_CLOSE_TRACE_FILE", "message":"OSS ASN.1 Error: Trace file error."},

0x80093100: { "code": "CRYPT_E_ASN1_ERROR", "message":"ASN1 Certificate encode/decode error code base."},

0x80093101: { "code": "CRYPT_E_ASN1_INTERNAL", "message":"ASN1 internal encode or decode error."},

0x80093102: { "code": "CRYPT_E_ASN1_EOD", "message":"ASN1 unexpected end of data."},

0x80093103: { "code": "CRYPT_E_ASN1_CORRUPT", "message":"ASN1 corrupted data."},

0x80093104: { "code": "CRYPT_E_ASN1_LARGE", "message":"ASN1 value too large."},

0x80093105: { "code": "CRYPT_E_ASN1_CONSTRAINT", "message":"ASN1 constraint violated."},

0x80093106: { "code": "CRYPT_E_ASN1_MEMORY", "message":"ASN1 out of memory."},

0x80093107: { "code": "CRYPT_E_ASN1_OVERFLOW", "message":"ASN1 buffer overflow."},

0x80093108: { "code": "CRYPT_E_ASN1_BADPDU", "message":"ASN1 function not supported for this protocol data unit (PDU)."},

0x80093109: { "code": "CRYPT_E_ASN1_BADARGS", "message":"ASN1 bad arguments to function call."},

0x8009310A: { "code": "CRYPT_E_ASN1_BADREAL", "message":"ASN1 bad real value."},

0x8009310B: { "code": "CRYPT_E_ASN1_BADTAG", "message":"ASN1 bad tag value met."},

0x8009310C: { "code": "CRYPT_E_ASN1_CHOICE", "message":"ASN1 bad choice value."},

0x8009310D: { "code": "CRYPT_E_ASN1_RULE", "message":"ASN1 bad encoding rule."},

0x8009310E: { "code": "CRYPT_E_ASN1_UTF8", "message":"ASN1 bad Unicode (UTF8)."},

0x80093133: { "code": "CRYPT_E_ASN1_PDU_TYPE", "message":"ASN1 bad PDU type."},

0x80093134: { "code": "CRYPT_E_ASN1_NYI", "message":"ASN1 not yet implemented."},

0x80093201: { "code": "CRYPT_E_ASN1_EXTENDED", "message":"ASN1 skipped unknown extensions."},

0x80093202: { "code": "CRYPT_E_ASN1_NOEOD", "message":"ASN1 end of data expected."},

0x80094001: { "code": "CERTSRV_E_BAD_REQUESTSUBJECT", "message":"The request subject name is invalid or too long."},

0x80094002: { "code": "CERTSRV_E_NO_REQUEST", "message":"The request does not exist."},

0x80094003: { "code": "CERTSRV_E_BAD_REQUESTSTATUS", "message":"The request's current status does not allow this operation."},

0x80094004: { "code": "CERTSRV_E_PROPERTY_EMPTY", "message":"The requested property value is empty."},

0x80094005: { "code": "CERTSRV_E_INVALID_CA_CERTIFICATE", "message":"The CA's certificate contains invalid data."},

0x80094006: { "code": "CERTSRV_E_SERVER_SUSPENDED", "message":"Certificate service has been suspended for a database restore operation."},

0x80094007: { "code": "CERTSRV_E_ENCODING_LENGTH", "message":"The certificate contains an encoded length that is potentially incompatible with older enrollment software."},

0x80094008: { "code": "CERTSRV_E_ROLECONFLICT", "message":"The operation is denied. The user has multiple roles assigned, and the CA is configured to enforce role separation."},

0x80094009: { "code": "CERTSRV_E_RESTRICTEDOFFICER", "message":"The operation is denied. It can only be performed by a certificate manager that is allowed to manage certificates for the current requester."},

0x8009400A: { "code": "CERTSRV_E_KEY_ARCHIVAL_NOT_CONFIGURED", "message":"Cannot archive private key. The CA is not configured for key archival."},

0x8009400B: { "code": "CERTSRV_E_NO_VALID_KRA", "message":"Cannot archive private key. The CA could not verify one or more key recovery certificates."},

0x8009400C: { "code": "CERTSRV_E_BAD_REQUEST_KEY_ARCHIVAL", "message":"The request is incorrectly formatted. The encrypted private key must be in an unauthenticated attribute in an outermost signature."},

0x8009400D: { "code": "CERTSRV_E_NO_CAADMIN_DEFINED", "message":"At least one security principal must have the permission to manage this CA."},

0x8009400E: { "code": "CERTSRV_E_BAD_RENEWAL_CERT_ATTRIBUTE", "message":"The request contains an invalid renewal certificate attribute."},

0x8009400F: { "code": "CERTSRV_E_NO_DB_SESSIONS", "message":"An attempt was made to open a CA database session, but there are already too many active sessions. The server needs to be configured to allow additional sessions."},

0x80094010: { "code": "CERTSRV_E_ALIGNMENT_FAULT", "message":"A memory reference caused a data alignment fault."},

0x80094011: { "code": "CERTSRV_E_ENROLL_DENIED", "message":"The permissions on this CA do not allow the current user to enroll for certificates."},

0x80094012: { "code": "CERTSRV_E_TEMPLATE_DENIED", "message":"The permissions on the certificate template do not allow the current user to enroll for this type of certificate."},

0x80094013: { "code": "CERTSRV_E_DOWNLEVEL_DC_SSL_OR_UPGRADE", "message":"The contacted domain controller cannot support signed Lightweight Directory Access Protocol (LDAP) traffic. Update the domain controller or configure Certificate Services to use SSL for Active Directory access."},

0x80094800: { "code": "CERTSRV_E_UNSUPPORTED_CERT_TYPE", "message":"The requested certificate template is not supported by this CA."},

0x80094801: { "code": "CERTSRV_E_NO_CERT_TYPE", "message":"The request contains no certificate template information."},

0x80094802: { "code": "CERTSRV_E_TEMPLATE_CONFLICT", "message":"The request contains conflicting template information."},

0x80094803: { "code": "CERTSRV_E_SUBJECT_ALT_NAME_REQUIRED", "message":"The request is missing a required Subject Alternate name extension."},

0x80094804: { "code": "CERTSRV_E_ARCHIVED_KEY_REQUIRED", "message":"The request is missing a required private key for archival by the server."},

0x80094805: { "code": "CERTSRV_E_SMIME_REQUIRED", "message":"The request is missing a required SMIME capabilities extension."},

0x80094806: { "code": "CERTSRV_E_BAD_RENEWAL_SUBJECT", "message":"The request was made on behalf of a subject other than the caller. The certificate template must be configured to require at least one signature to authorize the request."},

0x80094807: { "code": "CERTSRV_E_BAD_TEMPLATE_VERSION", "message":"The request template version is newer than the supported template version."},

0x80094808: { "code": "CERTSRV_E_TEMPLATE_POLICY_REQUIRED", "message":"The template is missing a required signature policy attribute."},

0x80094809: { "code": "CERTSRV_E_SIGNATURE_POLICY_REQUIRED", "message":"The request is missing required signature policy information."},

0x8009480A: { "code": "CERTSRV_E_SIGNATURE_COUNT", "message":"The request is missing one or more required signatures."},

0x8009480B: { "code": "CERTSRV_E_SIGNATURE_REJECTED", "message":"One or more signatures did not include the required application or issuance policies. The request is missing one or more required valid signatures."},

0x8009480C: { "code": "CERTSRV_E_ISSUANCE_POLICY_REQUIRED", "message":"The request is missing one or more required signature issuance policies."},

0x8009480D: { "code": "CERTSRV_E_SUBJECT_UPN_REQUIRED", "message":"The UPN is unavailable and cannot be added to the Subject Alternate name."},

0x8009480E: { "code": "CERTSRV_E_SUBJECT_DIRECTORY_GUID_REQUIRED", "message":"The Active Directory GUID is unavailable and cannot be added to the Subject Alternate name."},

0x8009480F: { "code": "CERTSRV_E_SUBJECT_DNS_REQUIRED", "message":"The Domain Name System (DNS) name is unavailable and cannot be added to the Subject Alternate name."},

0x80094810: { "code": "CERTSRV_E_ARCHIVED_KEY_UNEXPECTED", "message":"The request includes a private key for archival by the server, but key archival is not enabled for the specified certificate template."},

0x80094811: { "code": "CERTSRV_E_KEY_LENGTH", "message":"The public key does not meet the minimum size required by the specified certificate template."},

0x80094812: { "code": "CERTSRV_E_SUBJECT_EMAIL_REQUIRED", "message":"The email name is unavailable and cannot be added to the Subject or Subject Alternate name."},

0x80094813: { "code": "CERTSRV_E_UNKNOWN_CERT_TYPE", "message":"One or more certificate templates to be enabled on this CA could not be found."},

0x80094814: { "code": "CERTSRV_E_CERT_TYPE_OVERLAP", "message":"The certificate template renewal period is longer than the certificate validity period. The template should be reconfigured or the CA certificate renewed."},

0x80094815: { "code": "CERTSRV_E_TOO_MANY_SIGNATURES", "message":"The certificate template requires too many return authorization (RA) signatures. Only one RA signature is allowed."},

0x80094816: { "code": "CERTSRV_E_RENEWAL_BAD_PUBLIC_KEY", "message":"The key used in a renewal request does not match one of the certificates being renewed."},

0x80094817: { "code": "CERTSRV_E_INVALID_EK", "message":"The endorsement key certificate is not valid."},

0x8009481A: { "code": "CERTSRV_E_KEY_ATTESTATION", "message":"Key attestation did not succeed."},

0x80095000: { "code": "XENROLL_E_KEY_NOT_EXPORTABLE", "message":"The key is not exportable."},

0x80095001: { "code": "XENROLL_E_CANNOT_ADD_ROOT_CERT", "message":"You cannot add the root CA certificate into your local store."},

0x80095002: { "code": "XENROLL_E_RESPONSE_KA_HASH_NOT_FOUND", "message":"The key archival hash attribute was not found in the response."},

0x80095003: { "code": "XENROLL_E_RESPONSE_UNEXPECTED_KA_HASH", "message":"An unexpected key archival hash attribute was found in the response."},

0x80095004: { "code": "XENROLL_E_RESPONSE_KA_HASH_MISMATCH", "message":"There is a key archival hash mismatch between the request and the response."},

0x80095005: { "code": "XENROLL_E_KEYSPEC_SMIME_MISMATCH", "message":"Signing certificate cannot include SMIME extension."},

0x80096001: { "code": "TRUST_E_SYSTEM_ERROR", "message":"A system-level error occurred while verifying trust."},

0x80096002: { "code": "TRUST_E_NO_SIGNER_CERT", "message":"The certificate for the signer of the message is invalid or not found."},

0x80096003: { "code": "TRUST_E_COUNTER_SIGNER", "message":"One of the counter signatures was invalid."},

0x80096004: { "code": "TRUST_E_CERT_SIGNATURE", "message":"The signature of the certificate cannot be verified."},

0x80096005: { "code": "TRUST_E_TIME_STAMP", "message":"The time-stamp signature or certificate could not be verified or is malformed."},

0x80096010: { "code": "TRUST_E_BAD_DIGEST", "message":"The digital signature of the object did not verify."},

0x80096019: { "code": "TRUST_E_BASIC_CONSTRAINTS", "message":"A certificate's basic constraint extension has not been observed."},

0x8009601E: { "code": "TRUST_E_FINANCIAL_CRITERIA", "message":"The certificate does not meet or contain the Authenticode financial extensions."},

0x80097001: { "code": "MSSIPOTF_E_OUTOFMEMRANGE", "message":"Tried to reference a part of the file outside the proper range."},

0x80097002: { "code": "MSSIPOTF_E_CANTGETOBJECT", "message":"Could not retrieve an object from the file."},

0x80097003: { "code": "MSSIPOTF_E_NOHEADTABLE", "message":"Could not find the head table in the file."},

0x80097004: { "code": "MSSIPOTF_E_BAD_MAGICNUMBER", "message":"The magic number in the head table is incorrect."},

0x80097005: { "code": "MSSIPOTF_E_BAD_OFFSET_TABLE", "message":"The offset table has incorrect values."},

0x80097006: { "code": "MSSIPOTF_E_TABLE_TAGORDER", "message":"Duplicate table tags or the tags are out of alphabetical order."},

0x80097007: { "code": "MSSIPOTF_E_TABLE_LONGWORD", "message":"A table does not start on a long word boundary."},

0x80097008: { "code": "MSSIPOTF_E_BAD_FIRST_TABLE_PLACEMENT", "message":"First table does not appear after header information."},

0x80097009: { "code": "MSSIPOTF_E_TABLES_OVERLAP", "message":"Two or more tables overlap."},

0x8009700A: { "code": "MSSIPOTF_E_TABLE_PADBYTES", "message":"Too many pad bytes between tables, or pad bytes are not 0."},

0x8009700B: { "code": "MSSIPOTF_E_FILETOOSMALL", "message":"File is too small to contain the last table."},

0x8009700C: { "code": "MSSIPOTF_E_TABLE_CHECKSUM", "message":"A table checksum is incorrect."},

0x8009700D: { "code": "MSSIPOTF_E_FILE_CHECKSUM", "message":"The file checksum is incorrect."},

0x80097010: { "code": "MSSIPOTF_E_FAILED_POLICY", "message":"The signature does not have the correct attributes for the policy."},

0x80097011: { "code": "MSSIPOTF_E_FAILED_HINTS_CHECK", "message":"The file did not pass the hints check."},

0x80097012: { "code": "MSSIPOTF_E_NOT_OPENTYPE", "message":"The file is not an OpenType file."},

0x80097013: { "code": "MSSIPOTF_E_FILE", "message":"Failed on a file operation (such as open, map, read, or write)."},

0x80097014: { "code": "MSSIPOTF_E_CRYPT", "message":"A call to a CryptoAPI function failed."},

0x80097015: { "code": "MSSIPOTF_E_BADVERSION", "message":"There is a bad version number in the file."},

0x80097016: { "code": "MSSIPOTF_E_DSIG_STRUCTURE", "message":"The structure of the DSIG table is incorrect."},

0x80097017: { "code": "MSSIPOTF_E_PCONST_CHECK", "message":"A check failed in a partially constant table."},

0x80097018: { "code": "MSSIPOTF_E_STRUCTURE", "message":"Some kind of structural error."},

0x80097019: { "code": "ERROR_CRED_REQUIRES_CONFIRMATION", "message":"The requested credential requires confirmation."},

0x800B0001: { "code": "TRUST_E_PROVIDER_UNKNOWN", "message":"Unknown trust provider."},

0x800B0002: { "code": "TRUST_E_ACTION_UNKNOWN", "message":"The trust verification action specified is not supported by the specified trust provider."},

0x800B0003: { "code": "TRUST_E_SUBJECT_FORM_UNKNOWN", "message":"The form specified for the subject is not one supported or known by the specified trust provider."},

0x800B0004: { "code": "TRUST_E_SUBJECT_NOT_TRUSTED", "message":"The subject is not trusted for the specified action."},

0x800B0005: { "code": "DIGSIG_E_ENCODE", "message":"Error due to problem in ASN.1 encoding process."},

0x800B0006: { "code": "DIGSIG_E_DECODE", "message":"Error due to problem in ASN.1 decoding process."},

0x800B0007: { "code": "DIGSIG_E_EXTENSIBILITY", "message":"Reading/writing extensions where attributes are appropriate, and vice versa."},

0x800B0008: { "code": "DIGSIG_E_CRYPTO", "message":"Unspecified cryptographic failure."},

0x800B0009: { "code": "PERSIST_E_SIZEDEFINITE", "message":"The size of the data could not be determined."},

0x800B000A: { "code": "PERSIST_E_SIZEINDEFINITE", "message":"The size of the indefinite-sized data could not be determined."},

0x800B000B: { "code": "PERSIST_E_NOTSELFSIZING", "message":"This object does not read and write self-sizing data."},

0x800B0100: { "code": "TRUST_E_NOSIGNATURE", "message":"No signature was present in the subject."},

0x800B0101: { "code": "CERT_E_EXPIRED", "message":"A required certificate is not within its validity period when verifying against the current system clock or the time stamp in the signed file."},

0x800B0102: { "code": "CERT_E_VALIDITYPERIODNESTING", "message":"The validity periods of the certification chain do not nest correctly."},

0x800B0103: { "code": "CERT_E_ROLE", "message":"A certificate that can only be used as an end entity is being used as a CA or vice versa."},

0x800B0104: { "code": "CERT_E_PATHLENCONST", "message":"A path length constraint in the certification chain has been violated."},

0x800B0105: { "code": "CERT_E_CRITICAL", "message":"A certificate contains an unknown extension that is marked \"critical\"."},

0x800B0106: { "code": "CERT_E_PURPOSE", "message":"A certificate is being used for a purpose other than the ones specified by its CA."},

0x800B0107: { "code": "CERT_E_ISSUERCHAINING", "message":"A parent of a given certificate did not issue that child certificate."},

0x800B0108: { "code": "CERT_E_MALFORMED", "message":"A certificate is missing or has an empty value for an important field, such as a subject or issuer name."},

0x800B0109: { "code": "CERT_E_UNTRUSTEDROOT", "message":"A certificate chain processed, but terminated in a root certificate that is not trusted by the trust provider."},

0x800B010A: { "code": "CERT_E_CHAINING", "message":"A certificate chain could not be built to a trusted root authority."},

0x800B010B: { "code": "TRUST_E_FAIL", "message":"Generic trust failure."},

0x800B010C: { "code": "CERT_E_REVOKED", "message":"A certificate was explicitly revoked by its issuer. If the certificate is Microsoft Windows PCA 2010, then the driver was signed by a certificate no longer recognized by Windows.<3>"},

0x800B010D: { "code": "CERT_E_UNTRUSTEDTESTROOT", "message":"The certification path terminates with the test root that is not trusted with the current policy settings."},

0x800B010E: { "code": "CERT_E_REVOCATION_FAILURE", "message":"The revocation process could not continue—the certificates could not be checked."},

0x800B010F: { "code": "CERT_E_CN_NO_MATCH", "message":"The certificate's CN name does not match the passed value."},

0x800B0110: { "code": "CERT_E_WRONG_USAGE", "message":"The certificate is not valid for the requested usage."},

0x800B0111: { "code": "TRUST_E_EXPLICIT_DISTRUST", "message":"The certificate was explicitly marked as untrusted by the user."},

0x800B0112: { "code": "CERT_E_UNTRUSTEDCA", "message":"A certification chain processed correctly, but one of the CA certificates is not trusted by the policy provider."},

0x800B0113: { "code": "CERT_E_INVALID_POLICY", "message":"The certificate has invalid policy."},

0x800B0114: { "code": "CERT_E_INVALID_NAME", "message":"The certificate has an invalid name. The name is not included in the permitted list or is explicitly excluded."},

0x800D0003: { "code": "NS_W_SERVER_BANDWIDTH_LIMIT", "message":"The maximum filebitrate value specified is greater than the server's configured maximum bandwidth."},

0x800D0004: { "code": "NS_W_FILE_BANDWIDTH_LIMIT", "message":"The maximum bandwidth value specified is less than the maximum filebitrate."},

0x800D0060: { "code": "NS_W_UNKNOWN_EVENT", "message":"Unknown %1 event encountered."},

0x800D0199: { "code": "NS_I_CATATONIC_FAILURE", "message":"Disk %1 ( %2 ) on Content Server %3, will be failed because it is catatonic."},

0x800D019A: { "code": "NS_I_CATATONIC_AUTO_UNFAIL", "message":"Disk %1 ( %2 ) on Content Server %3, auto online from catatonic state."},

0x800F0000: { "code": "SPAPI_E_EXPECTED_SECTION_NAME", "message":"A non-empty line was encountered in the INF before the start of a section."},

0x800F0001: { "code": "SPAPI_E_BAD_SECTION_NAME_LINE", "message":"A section name marker in the information file (INF) is not complete or does not exist on a line by itself."},

0x800F0002: { "code": "SPAPI_E_SECTION_NAME_TOO_LONG", "message":"An INF section was encountered whose name exceeds the maximum section name length."},

0x800F0003: { "code": "SPAPI_E_GENERAL_SYNTAX", "message":"The syntax of the INF is invalid."},

0x800F0100: { "code": "SPAPI_E_WRONG_INF_STYLE", "message":"The style of the INF is different than what was requested."},

0x800F0101: { "code": "SPAPI_E_SECTION_NOT_FOUND", "message":"The required section was not found in the INF."},

0x800F0102: { "code": "SPAPI_E_LINE_NOT_FOUND", "message":"The required line was not found in the INF."},

0x800F0103: { "code": "SPAPI_E_NO_BACKUP", "message":"The files affected by the installation of this file queue have not been backed up for uninstall."},

0x800F0200: { "code": "SPAPI_E_NO_ASSOCIATED_CLASS", "message":"The INF or the device information set or element does not have an associated install class."},

0x800F0201: { "code": "SPAPI_E_CLASS_MISMATCH", "message":"The INF or the device information set or element does not match the specified install class."},

0x800F0202: { "code": "SPAPI_E_DUPLICATE_FOUND", "message":"An existing device was found that is a duplicate of the device being manually installed."},

0x800F0203: { "code": "SPAPI_E_NO_DRIVER_SELECTED", "message":"There is no driver selected for the device information set or element."},

0x800F0204: { "code": "SPAPI_E_KEY_DOES_NOT_EXIST", "message":"The requested device registry key does not exist."},

0x800F0205: { "code": "SPAPI_E_INVALID_DEVINST_NAME", "message":"The device instance name is invalid."},

0x800F0206: { "code": "SPAPI_E_INVALID_CLASS", "message":"The install class is not present or is invalid."},

0x800F0207: { "code": "SPAPI_E_DEVINST_ALREADY_EXISTS", "message":"The device instance cannot be created because it already exists."},

0x800F0208: { "code": "SPAPI_E_DEVINFO_NOT_REGISTERED", "message":"The operation cannot be performed on a device information element that has not been registered."},

0x800F0209: { "code": "SPAPI_E_INVALID_REG_PROPERTY", "message":"The device property code is invalid."},

0x800F020A: { "code": "SPAPI_E_NO_INF", "message":"The INF from which a driver list is to be built does not exist."},

0x800F020B: { "code": "SPAPI_E_NO_SUCH_DEVINST", "message":"The device instance does not exist in the hardware tree."},

0x800F020C: { "code": "SPAPI_E_CANT_LOAD_CLASS_ICON", "message":"The icon representing this install class cannot be loaded."},

0x800F020D: { "code": "SPAPI_E_INVALID_CLASS_INSTALLER", "message":"The class installer registry entry is invalid."},

0x800F020E: { "code": "SPAPI_E_DI_DO_DEFAULT", "message":"The class installer has indicated that the default action should be performed for this installation request."},

0x800F020F: { "code": "SPAPI_E_DI_NOFILECOPY", "message":"The operation does not require any files to be copied."},

0x800F0210: { "code": "SPAPI_E_INVALID_HWPROFILE", "message":"The specified hardware profile does not exist."},

0x800F0211: { "code": "SPAPI_E_NO_DEVICE_SELECTED", "message":"There is no device information element currently selected for this device information set."},

0x800F0212: { "code": "SPAPI_E_DEVINFO_LIST_LOCKED", "message":"The operation cannot be performed because the device information set is locked."},

0x800F0213: { "code": "SPAPI_E_DEVINFO_DATA_LOCKED", "message":"The operation cannot be performed because the device information element is locked."},

0x800F0214: { "code": "SPAPI_E_DI_BAD_PATH", "message":"The specified path does not contain any applicable device INFs."},

0x800F0215: { "code": "SPAPI_E_NO_CLASSINSTALL_PARAMS", "message":"No class installer parameters have been set for the device information set or element."},

0x800F0216: { "code": "SPAPI_E_FILEQUEUE_LOCKED", "message":"The operation cannot be performed because the file queue is locked."},

0x800F0217: { "code": "SPAPI_E_BAD_SERVICE_INSTALLSECT", "message":"A service installation section in this INF is invalid."},

0x800F0218: { "code": "SPAPI_E_NO_CLASS_DRIVER_LIST", "message":"There is no class driver list for the device information element."},

0x800F0219: { "code": "SPAPI_E_NO_ASSOCIATED_SERVICE", "message":"The installation failed because a function driver was not specified for this device instance."},

0x800F021A: { "code": "SPAPI_E_NO_DEFAULT_DEVICE_INTERFACE", "message":"There is presently no default device interface designated for this interface class."},

0x800F021B: { "code": "SPAPI_E_DEVICE_INTERFACE_ACTIVE", "message":"The operation cannot be performed because the device interface is currently active."},

0x800F021C: { "code": "SPAPI_E_DEVICE_INTERFACE_REMOVED", "message":"The operation cannot be performed because the device interface has been removed from the system."},

0x800F021D: { "code": "SPAPI_E_BAD_INTERFACE_INSTALLSECT", "message":"An interface installation section in this INF is invalid."},

0x800F021E: { "code": "SPAPI_E_NO_SUCH_INTERFACE_CLASS", "message":"This interface class does not exist in the system."},

0x800F021F: { "code": "SPAPI_E_INVALID_REFERENCE_STRING", "message":"The reference string supplied for this interface device is invalid."},

0x800F0220: { "code": "SPAPI_E_INVALID_MACHINENAME", "message":"The specified machine name does not conform to Universal Naming Convention (UNCs)."},

0x800F0221: { "code": "SPAPI_E_REMOTE_COMM_FAILURE", "message":"A general remote communication error occurred."},

0x800F0222: { "code": "SPAPI_E_MACHINE_UNAVAILABLE", "message":"The machine selected for remote communication is not available at this time."},

0x800F0223: { "code": "SPAPI_E_NO_CONFIGMGR_SERVICES", "message":"The Plug and Play service is not available on the remote machine."},

0x800F0224: { "code": "SPAPI_E_INVALID_PROPPAGE_PROVIDER", "message":"The property page provider registry entry is invalid."},

0x800F0225: { "code": "SPAPI_E_NO_SUCH_DEVICE_INTERFACE", "message":"The requested device interface is not present in the system."},

0x800F0226: { "code": "SPAPI_E_DI_POSTPROCESSING_REQUIRED", "message":"The device's co-installer has additional work to perform after installation is complete."},

0x800F0227: { "code": "SPAPI_E_INVALID_COINSTALLER", "message":"The device's co-installer is invalid."},

0x800F0228: { "code": "SPAPI_E_NO_COMPAT_DRIVERS", "message":"There are no compatible drivers for this device."},

0x800F0229: { "code": "SPAPI_E_NO_DEVICE_ICON", "message":"There is no icon that represents this device or device type."},

0x800F022A: { "code": "SPAPI_E_INVALID_INF_LOGCONFIG", "message":"A logical configuration specified in this INF is invalid."},

0x800F022B: { "code": "SPAPI_E_DI_DONT_INSTALL", "message":"The class installer has denied the request to install or upgrade this device."},

0x800F022C: { "code": "SPAPI_E_INVALID_FILTER_DRIVER", "message":"One of the filter drivers installed for this device is invalid."},

0x800F022D: { "code": "SPAPI_E_NON_WINDOWS_NT_DRIVER", "message":"The driver selected for this device does not support Windows XP operating system."},

0x800F022E: { "code": "SPAPI_E_NON_WINDOWS_DRIVER", "message":"The driver selected for this device does not support Windows."},

0x800F022F: { "code": "SPAPI_E_NO_CATALOG_FOR_OEM_INF", "message":"The third-party INF does not contain digital signature information."},

0x800F0230: { "code": "SPAPI_E_DEVINSTALL_QUEUE_NONNATIVE", "message":"An invalid attempt was made to use a device installation file queue for verification of digital signatures relative to other platforms."},

0x800F0231: { "code": "SPAPI_E_NOT_DISABLEABLE", "message":"The device cannot be disabled."},

0x800F0232: { "code": "SPAPI_E_CANT_REMOVE_DEVINST", "message":"The device could not be dynamically removed."},

0x800F0233: { "code": "SPAPI_E_INVALID_TARGET", "message":"Cannot copy to specified target."},

0x800F0234: { "code": "SPAPI_E_DRIVER_NONNATIVE", "message":"Driver is not intended for this platform."},

0x800F0235: { "code": "SPAPI_E_IN_WOW64", "message":"Operation not allowed in WOW64."},

0x800F0236: { "code": "SPAPI_E_SET_SYSTEM_RESTORE_POINT", "message":"The operation involving unsigned file copying was rolled back, so that a system restore point could be set."},

0x800F0237: { "code": "SPAPI_E_INCORRECTLY_COPIED_INF", "message":"An INF was copied into the Windows INF directory in an improper manner."},

0x800F0238: { "code": "SPAPI_E_SCE_DISABLED", "message":"The Security Configuration Editor (SCE) APIs have been disabled on this embedded product."},

0x800F0239: { "code": "SPAPI_E_UNKNOWN_EXCEPTION", "message":"An unknown exception was encountered."},

0x800F023A: { "code": "SPAPI_E_PNP_REGISTRY_ERROR", "message":"A problem was encountered when accessing the Plug and Play registry database."},

0x800F023B: { "code": "SPAPI_E_REMOTE_REQUEST_UNSUPPORTED", "message":"The requested operation is not supported for a remote machine."},

0x800F023C: { "code": "SPAPI_E_NOT_AN_INSTALLED_OEM_INF", "message":"The specified file is not an installed original equipment manufacturer (OEM) INF."},

0x800F023D: { "code": "SPAPI_E_INF_IN_USE_BY_DEVICES", "message":"One or more devices are presently installed using the specified INF."},

0x800F023E: { "code": "SPAPI_E_DI_FUNCTION_OBSOLETE", "message":"The requested device install operation is obsolete."},

0x800F023F: { "code": "SPAPI_E_NO_AUTHENTICODE_CATALOG", "message":"A file could not be verified because it does not have an associated catalog signed via Authenticode."},

0x800F0240: { "code": "SPAPI_E_AUTHENTICODE_DISALLOWED", "message":"Authenticode signature verification is not supported for the specified INF."},

0x800F0241: { "code": "SPAPI_E_AUTHENTICODE_TRUSTED_PUBLISHER", "message":"The INF was signed with an Authenticode catalog from a trusted publisher."},

0x800F0242: { "code": "SPAPI_E_AUTHENTICODE_TRUST_NOT_ESTABLISHED", "message":"The publisher of an Authenticode-signed catalog has not yet been established as trusted."},

0x800F0243: { "code": "SPAPI_E_AUTHENTICODE_PUBLISHER_NOT_TRUSTED", "message":"The publisher of an Authenticode-signed catalog was not established as trusted."},

0x800F0244: { "code": "SPAPI_E_SIGNATURE_OSATTRIBUTE_MISMATCH", "message":"The software was tested for compliance with Windows logo requirements on a different version of Windows and might not be compatible with this version."},

0x800F0245: { "code": "SPAPI_E_ONLY_VALIDATE_VIA_AUTHENTICODE", "message":"The file can be validated only by a catalog signed via Authenticode."},

0x800F0246: { "code": "SPAPI_E_DEVICE_INSTALLER_NOT_READY", "message":"One of the installers for this device cannot perform the installation at this time."},

0x800F0247: { "code": "SPAPI_E_DRIVER_STORE_ADD_FAILED", "message":"A problem was encountered while attempting to add the driver to the store."},

0x800F0248: { "code": "SPAPI_E_DEVICE_INSTALL_BLOCKED", "message":"The installation of this device is forbidden by system policy. Contact your system administrator."},

0x800F0249: { "code": "SPAPI_E_DRIVER_INSTALL_BLOCKED", "message":"The installation of this driver is forbidden by system policy. Contact your system administrator."},

0x800F024A: { "code": "SPAPI_E_WRONG_INF_TYPE", "message":"The specified INF is the wrong type for this operation."},

0x800F024B: { "code": "SPAPI_E_FILE_HASH_NOT_IN_CATALOG", "message":"The hash for the file is not present in the specified catalog file. The file is likely corrupt or the victim of tampering."},

0x800F024C: { "code": "SPAPI_E_DRIVER_STORE_DELETE_FAILED", "message":"A problem was encountered while attempting to delete the driver from the store."},

0x800F0300: { "code": "SPAPI_E_UNRECOVERABLE_STACK_OVERFLOW", "message":"An unrecoverable stack overflow was encountered."},

0x800F1000: { "code": "SPAPI_E_ERROR_NOT_INSTALLED", "message":"No installed components were detected."},

0x80100001: { "code": "SCARD_F_INTERNAL_ERROR", "message":"An internal consistency check failed."},

0x80100002: { "code": "SCARD_E_CANCELLED", "message":"The action was canceled by an SCardCancel request."},

0x80100003: { "code": "SCARD_E_INVALID_HANDLE", "message":"The supplied handle was invalid."},

0x80100004: { "code": "SCARD_E_INVALID_PARAMETER", "message":"One or more of the supplied parameters could not be properly interpreted."},

0x80100005: { "code": "SCARD_E_INVALID_TARGET", "message":"Registry startup information is missing or invalid."},

0x80100006: { "code": "SCARD_E_NO_MEMORY", "message":"Not enough memory available to complete this command."},

0x80100007: { "code": "SCARD_F_WAITED_TOO_LONG", "message":"An internal consistency timer has expired."},

0x80100008: { "code": "SCARD_E_INSUFFICIENT_BUFFER", "message":"The data buffer to receive returned data is too small for the returned data."},

0x80100009: { "code": "SCARD_E_UNKNOWN_READER", "message":"The specified reader name is not recognized."},

0x8010000A: { "code": "SCARD_E_TIMEOUT", "message":"The user-specified time-out value has expired."},

0x8010000B: { "code": "SCARD_E_SHARING_VIOLATION", "message":"The smart card cannot be accessed because of other connections outstanding."},

0x8010000C: { "code": "SCARD_E_NO_SMARTCARD", "message":"The operation requires a smart card, but no smart card is currently in the device."},

0x8010000D: { "code": "SCARD_E_UNKNOWN_CARD", "message":"The specified smart card name is not recognized."},

0x8010000E: { "code": "SCARD_E_CANT_DISPOSE", "message":"The system could not dispose of the media in the requested manner."},

0x8010000F: { "code": "SCARD_E_PROTO_MISMATCH", "message":"The requested protocols are incompatible with the protocol currently in use with the smart card."},

0x80100010: { "code": "SCARD_E_NOT_READY", "message":"The reader or smart card is not ready to accept commands."},

0x80100011: { "code": "SCARD_E_INVALID_VALUE", "message":"One or more of the supplied parameters values could not be properly interpreted."},

0x80100012: { "code": "SCARD_E_SYSTEM_CANCELLED", "message":"The action was canceled by the system, presumably to log off or shut down."},

0x80100013: { "code": "SCARD_F_COMM_ERROR", "message":"An internal communications error has been detected."},

0x80100014: { "code": "SCARD_F_UNKNOWN_ERROR", "message":"An internal error has been detected, but the source is unknown."},

0x80100015: { "code": "SCARD_E_INVALID_ATR", "message":"An automatic terminal recognition (ATR) obtained from the registry is not a valid ATR string."},

0x80100016: { "code": "SCARD_E_NOT_TRANSACTED", "message":"An attempt was made to end a nonexistent transaction."},

0x80100017: { "code": "SCARD_E_READER_UNAVAILABLE", "message":"The specified reader is not currently available for use."},

0x80100018: { "code": "SCARD_P_SHUTDOWN", "message":"The operation has been aborted to allow the server application to exit."},

0x80100019: { "code": "SCARD_E_PCI_TOO_SMALL", "message":"The peripheral component interconnect (PCI) Receive buffer was too small."},

0x8010001A: { "code": "SCARD_E_READER_UNSUPPORTED", "message":"The reader driver does not meet minimal requirements for support."},

0x8010001B: { "code": "SCARD_E_DUPLICATE_READER", "message":"The reader driver did not produce a unique reader name."},

0x8010001C: { "code": "SCARD_E_CARD_UNSUPPORTED", "message":"The smart card does not meet minimal requirements for support."},

0x8010001D: { "code": "SCARD_E_NO_SERVICE", "message":"The smart card resource manager is not running."},

0x8010001E: { "code": "SCARD_E_SERVICE_STOPPED", "message":"The smart card resource manager has shut down."},

0x8010001F: { "code": "SCARD_E_UNEXPECTED", "message":"An unexpected card error has occurred."},

0x80100020: { "code": "SCARD_E_ICC_INSTALLATION", "message":"No primary provider can be found for the smart card."},

0x80100021: { "code": "SCARD_E_ICC_CREATEORDER", "message":"The requested order of object creation is not supported."},

0x80100022: { "code": "SCARD_E_UNSUPPORTED_FEATURE", "message":"This smart card does not support the requested feature."},

0x80100023: { "code": "SCARD_E_DIR_NOT_FOUND", "message":"The identified directory does not exist in the smart card."},

0x80100024: { "code": "SCARD_E_FILE_NOT_FOUND", "message":"The identified file does not exist in the smart card."},

0x80100025: { "code": "SCARD_E_NO_DIR", "message":"The supplied path does not represent a smart card directory."},

0x80100026: { "code": "SCARD_E_NO_FILE", "message":"The supplied path does not represent a smart card file."},

0x80100027: { "code": "SCARD_E_NO_ACCESS", "message":"Access is denied to this file."},

0x80100028: { "code": "SCARD_E_WRITE_TOO_MANY", "message":"The smart card does not have enough memory to store the information."},

0x80100029: { "code": "SCARD_E_BAD_SEEK", "message":"There was an error trying to set the smart card file object pointer."},

0x8010002A: { "code": "SCARD_E_INVALID_CHV", "message":"The supplied PIN is incorrect."},

0x8010002B: { "code": "SCARD_E_UNKNOWN_RES_MNG", "message":"An unrecognized error code was returned from a layered component."},

0x8010002C: { "code": "SCARD_E_NO_SUCH_CERTIFICATE", "message":"The requested certificate does not exist."},

0x8010002D: { "code": "SCARD_E_CERTIFICATE_UNAVAILABLE", "message":"The requested certificate could not be obtained."},

0x8010002E: { "code": "SCARD_E_NO_READERS_AVAILABLE", "message":"Cannot find a smart card reader."},

0x8010002F: { "code": "SCARD_E_COMM_DATA_LOST", "message":"A communications error with the smart card has been detected. Retry the operation."},

0x80100030: { "code": "SCARD_E_NO_KEY_CONTAINER", "message":"The requested key container does not exist on the smart card."},

0x80100031: { "code": "SCARD_E_SERVER_TOO_BUSY", "message":"The smart card resource manager is too busy to complete this operation."},

0x80100065: { "code": "SCARD_W_UNSUPPORTED_CARD", "message":"The reader cannot communicate with the smart card, due to ATR configuration conflicts."},

0x80100066: { "code": "SCARD_W_UNRESPONSIVE_CARD", "message":"The smart card is not responding to a reset."},

0x80100067: { "code": "SCARD_W_UNPOWERED_CARD", "message":"Power has been removed from the smart card, so that further communication is not possible."},

0x80100068: { "code": "SCARD_W_RESET_CARD", "message":"The smart card has been reset, so any shared state information is invalid."},

0x80100069: { "code": "SCARD_W_REMOVED_CARD", "message":"The smart card has been removed, so that further communication is not possible."},

0x8010006A: { "code": "SCARD_W_SECURITY_VIOLATION", "message":"Access was denied because of a security violation."},

0x8010006B: { "code": "SCARD_W_WRONG_CHV", "message":"The card cannot be accessed because the wrong PIN was presented."},

0x8010006C: { "code": "SCARD_W_CHV_BLOCKED", "message":"The card cannot be accessed because the maximum number of PIN entry attempts has been reached."},

0x8010006D: { "code": "SCARD_W_EOF", "message":"The end of the smart card file has been reached."},

0x8010006E: { "code": "SCARD_W_CANCELLED_BY_USER", "message":"The action was canceled by the user."},

0x8010006F: { "code": "SCARD_W_CARD_NOT_AUTHENTICATED", "message":"No PIN was presented to the smart card."},

0x80110401: { "code": "COMADMIN_E_OBJECTERRORS", "message":"Errors occurred accessing one or more objects—the ErrorInfo collection contains more detail."},

0x80110402: { "code": "COMADMIN_E_OBJECTINVALID", "message":"One or more of the object's properties are missing or invalid."},

0x80110403: { "code": "COMADMIN_E_KEYMISSING", "message":"The object was not found in the catalog."},

0x80110404: { "code": "COMADMIN_E_ALREADYINSTALLED", "message":"The object is already registered."},

0x80110407: { "code": "COMADMIN_E_APP_FILE_WRITEFAIL", "message":"An error occurred writing to the application file."},

0x80110408: { "code": "COMADMIN_E_APP_FILE_READFAIL", "message":"An error occurred reading the application file."},

0x80110409: { "code": "COMADMIN_E_APP_FILE_VERSION", "message":"Invalid version number in application file."},

0x8011040A: { "code": "COMADMIN_E_BADPATH", "message":"The file path is invalid."},

0x8011040B: { "code": "COMADMIN_E_APPLICATIONEXISTS", "message":"The application is already installed."},

0x8011040C: { "code": "COMADMIN_E_ROLEEXISTS", "message":"The role already exists."},

0x8011040D: { "code": "COMADMIN_E_CANTCOPYFILE", "message":"An error occurred copying the file."},

0x8011040F: { "code": "COMADMIN_E_NOUSER", "message":"One or more users are not valid."},

0x80110410: { "code": "COMADMIN_E_INVALIDUSERIDS", "message":"One or more users in the application file are not valid."},

0x80110411: { "code": "COMADMIN_E_NOREGISTRYCLSID", "message":"The component's CLSID is missing or corrupt."},

0x80110412: { "code": "COMADMIN_E_BADREGISTRYPROGID", "message":"The component's programmatic ID is missing or corrupt."},

0x80110413: { "code": "COMADMIN_E_AUTHENTICATIONLEVEL", "message":"Unable to set required authentication level for update request."},

0x80110414: { "code": "COMADMIN_E_USERPASSWDNOTVALID", "message":"The identity or password set on the application is not valid."},

0x80110418: { "code": "COMADMIN_E_CLSIDORIIDMISMATCH", "message":"Application file CLSIDs or instance identifiers (IIDs) do not match corresponding DLLs."},

0x80110419: { "code": "COMADMIN_E_REMOTEINTERFACE", "message":"Interface information is either missing or changed."},

0x8011041A: { "code": "COMADMIN_E_DLLREGISTERSERVER", "message":"DllRegisterServer failed on component install."},

0x8011041B: { "code": "COMADMIN_E_NOSERVERSHARE", "message":"No server file share available."},

0x8011041D: { "code": "COMADMIN_E_DLLLOADFAILED", "message":"DLL could not be loaded."},

0x8011041E: { "code": "COMADMIN_E_BADREGISTRYLIBID", "message":"The registered TypeLib ID is not valid."},

0x8011041F: { "code": "COMADMIN_E_APPDIRNOTFOUND", "message":"Application install directory not found."},

0x80110423: { "code": "COMADMIN_E_REGISTRARFAILED", "message":"Errors occurred while in the component registrar."},

0x80110424: { "code": "COMADMIN_E_COMPFILE_DOESNOTEXIST", "message":"The file does not exist."},

0x80110425: { "code": "COMADMIN_E_COMPFILE_LOADDLLFAIL", "message":"The DLL could not be loaded."},

0x80110426: { "code": "COMADMIN_E_COMPFILE_GETCLASSOBJ", "message":"GetClassObject failed in the DLL."},

0x80110427: { "code": "COMADMIN_E_COMPFILE_CLASSNOTAVAIL", "message":"The DLL does not support the components listed in the TypeLib."},

0x80110428: { "code": "COMADMIN_E_COMPFILE_BADTLB", "message":"The TypeLib could not be loaded."},

0x80110429: { "code": "COMADMIN_E_COMPFILE_NOTINSTALLABLE", "message":"The file does not contain components or component information."},

0x8011042A: { "code": "COMADMIN_E_NOTCHANGEABLE", "message":"Changes to this object and its subobjects have been disabled."},

0x8011042B: { "code": "COMADMIN_E_NOTDELETEABLE", "message":"The delete function has been disabled for this object."},

0x8011042C: { "code": "COMADMIN_E_SESSION", "message":"The server catalog version is not supported."},

0x8011042D: { "code": "COMADMIN_E_COMP_MOVE_LOCKED", "message":"The component move was disallowed because the source or destination application is either a system application or currently locked against changes."},

0x8011042E: { "code": "COMADMIN_E_COMP_MOVE_BAD_DEST", "message":"The component move failed because the destination application no longer exists."},

0x80110430: { "code": "COMADMIN_E_REGISTERTLB", "message":"The system was unable to register the TypeLib."},

0x80110433: { "code": "COMADMIN_E_SYSTEMAPP", "message":"This operation cannot be performed on the system application."},

0x80110434: { "code": "COMADMIN_E_COMPFILE_NOREGISTRAR", "message":"The component registrar referenced in this file is not available."},

0x80110435: { "code": "COMADMIN_E_COREQCOMPINSTALLED", "message":"A component in the same DLL is already installed."},

0x80110436: { "code": "COMADMIN_E_SERVICENOTINSTALLED", "message":"The service is not installed."},

0x80110437: { "code": "COMADMIN_E_PROPERTYSAVEFAILED", "message":"One or more property settings are either invalid or in conflict with each other."},

0x80110438: { "code": "COMADMIN_E_OBJECTEXISTS", "message":"The object you are attempting to add or rename already exists."},

0x80110439: { "code": "COMADMIN_E_COMPONENTEXISTS", "message":"The component already exists."},

0x8011043B: { "code": "COMADMIN_E_REGFILE_CORRUPT", "message":"The registration file is corrupt."},

0x8011043C: { "code": "COMADMIN_E_PROPERTY_OVERFLOW", "message":"The property value is too large."},

0x8011043E: { "code": "COMADMIN_E_NOTINREGISTRY", "message":"Object was not found in registry."},

0x8011043F: { "code": "COMADMIN_E_OBJECTNOTPOOLABLE", "message":"This object cannot be pooled."},

0x80110446: { "code": "COMADMIN_E_APPLID_MATCHES_CLSID", "message":"A CLSID with the same GUID as the new application ID is already installed on this machine."},

0x80110447: { "code": "COMADMIN_E_ROLE_DOES_NOT_EXIST", "message":"A role assigned to a component, interface, or method did not exist in the application."},

0x80110448: { "code": "COMADMIN_E_START_APP_NEEDS_COMPONENTS", "message":"You must have components in an application to start the application."},

0x80110449: { "code": "COMADMIN_E_REQUIRES_DIFFERENT_PLATFORM", "message":"This operation is not enabled on this platform."},

0x8011044A: { "code": "COMADMIN_E_CAN_NOT_EXPORT_APP_PROXY", "message":"Application proxy is not exportable."},

0x8011044B: { "code": "COMADMIN_E_CAN_NOT_START_APP", "message":"Failed to start application because it is either a library application or an application proxy."},

0x8011044C: { "code": "COMADMIN_E_CAN_NOT_EXPORT_SYS_APP", "message":"System application is not exportable."},

0x8011044D: { "code": "COMADMIN_E_CANT_SUBSCRIBE_TO_COMPONENT", "message":"Cannot subscribe to this component (the component might have been imported)."},

0x8011044E: { "code": "COMADMIN_E_EVENTCLASS_CANT_BE_SUBSCRIBER", "message":"An event class cannot also be a subscriber component."},

0x8011044F: { "code": "COMADMIN_E_LIB_APP_PROXY_INCOMPATIBLE", "message":"Library applications and application proxies are incompatible."},

0x80110450: { "code": "COMADMIN_E_BASE_PARTITION_ONLY", "message":"This function is valid for the base partition only."},

0x80110451: { "code": "COMADMIN_E_START_APP_DISABLED", "message":"You cannot start an application that has been disabled."},

0x80110457: { "code": "COMADMIN_E_CAT_DUPLICATE_PARTITION_NAME", "message":"The specified partition name is already in use on this computer."},

0x80110458: { "code": "COMADMIN_E_CAT_INVALID_PARTITION_NAME", "message":"The specified partition name is invalid. Check that the name contains at least one visible character."},

0x80110459: { "code": "COMADMIN_E_CAT_PARTITION_IN_USE", "message":"The partition cannot be deleted because it is the default partition for one or more users."},

0x8011045A: { "code": "COMADMIN_E_FILE_PARTITION_DUPLICATE_FILES", "message":"The partition cannot be exported because one or more components in the partition have the same file name."},

0x8011045B: { "code": "COMADMIN_E_CAT_IMPORTED_COMPONENTS_NOT_ALLOWED", "message":"Applications that contain one or more imported components cannot be installed into a nonbase partition."},

0x8011045C: { "code": "COMADMIN_E_AMBIGUOUS_APPLICATION_NAME", "message":"The application name is not unique and cannot be resolved to an application ID."},

0x8011045D: { "code": "COMADMIN_E_AMBIGUOUS_PARTITION_NAME", "message":"The partition name is not unique and cannot be resolved to a partition ID."},

0x80110472: { "code": "COMADMIN_E_REGDB_NOTINITIALIZED", "message":"The COM+ registry database has not been initialized."},

0x80110473: { "code": "COMADMIN_E_REGDB_NOTOPEN", "message":"The COM+ registry database is not open."},

0x80110474: { "code": "COMADMIN_E_REGDB_SYSTEMERR", "message":"The COM+ registry database detected a system error."},

0x80110475: { "code": "COMADMIN_E_REGDB_ALREADYRUNNING", "message":"The COM+ registry database is already running."},

0x80110480: { "code": "COMADMIN_E_MIG_VERSIONNOTSUPPORTED", "message":"This version of the COM+ registry database cannot be migrated."},

0x80110481: { "code": "COMADMIN_E_MIG_SCHEMANOTFOUND", "message":"The schema version to be migrated could not be found in the COM+ registry database."},

0x80110482: { "code": "COMADMIN_E_CAT_BITNESSMISMATCH", "message":"There was a type mismatch between binaries."},

0x80110483: { "code": "COMADMIN_E_CAT_UNACCEPTABLEBITNESS", "message":"A binary of unknown or invalid type was provided."},

0x80110484: { "code": "COMADMIN_E_CAT_WRONGAPPBITNESS", "message":"There was a type mismatch between a binary and an application."},

0x80110485: { "code": "COMADMIN_E_CAT_PAUSE_RESUME_NOT_SUPPORTED", "message":"The application cannot be paused or resumed."},

0x80110486: { "code": "COMADMIN_E_CAT_SERVERFAULT", "message":"The COM+ catalog server threw an exception during execution."},

0x80110600: { "code": "COMQC_E_APPLICATION_NOT_QUEUED", "message":"Only COM+ applications marked \"queued\" can be invoked using the \"queue\" moniker."},

0x80110601: { "code": "COMQC_E_NO_QUEUEABLE_INTERFACES", "message":"At least one interface must be marked \"queued\" to create a queued component instance with the \"queue\" moniker."},

0x80110602: { "code": "COMQC_E_QUEUING_SERVICE_NOT_AVAILABLE", "message":"Message Queuing is required for the requested operation and is not installed."},

0x80110603: { "code": "COMQC_E_NO_IPERSISTSTREAM", "message":"Unable to marshal an interface that does not support IPersistStream."},

0x80110604: { "code": "COMQC_E_BAD_MESSAGE", "message":"The message is improperly formatted or was damaged in transit."},

0x80110605: { "code": "COMQC_E_UNAUTHENTICATED", "message":"An unauthenticated message was received by an application that accepts only authenticated messages."},

0x80110606: { "code": "COMQC_E_UNTRUSTED_ENQUEUER", "message":"The message was requeued or moved by a user not in the QC Trusted User \"role\"."},

0x80110701: { "code": "MSDTC_E_DUPLICATE_RESOURCE", "message":"Cannot create a duplicate resource of type Distributed Transaction Coordinator."},

0x80110808: { "code": "COMADMIN_E_OBJECT_PARENT_MISSING", "message":"One of the objects being inserted or updated does not belong to a valid parent collection."},

0x80110809: { "code": "COMADMIN_E_OBJECT_DOES_NOT_EXIST", "message":"One of the specified objects cannot be found."},

0x8011080A: { "code": "COMADMIN_E_APP_NOT_RUNNING", "message":"The specified application is not currently running."},

0x8011080B: { "code": "COMADMIN_E_INVALID_PARTITION", "message":"The partitions specified are not valid."},

0x8011080D: { "code": "COMADMIN_E_SVCAPP_NOT_POOLABLE_OR_RECYCLABLE", "message":"COM+ applications that run as Windows NT service cannot be pooled or recycled."},

0x8011080E: { "code": "COMADMIN_E_USER_IN_SET", "message":"One or more users are already assigned to a local partition set."},

0x8011080F: { "code": "COMADMIN_E_CANTRECYCLELIBRARYAPPS", "message":"Library applications cannot be recycled."},

0x80110811: { "code": "COMADMIN_E_CANTRECYCLESERVICEAPPS", "message":"Applications running as Windows NT services cannot be recycled."},

0x80110812: { "code": "COMADMIN_E_PROCESSALREADYRECYCLED", "message":"The process has already been recycled."},

0x80110813: { "code": "COMADMIN_E_PAUSEDPROCESSMAYNOTBERECYCLED", "message":"A paused process cannot be recycled."},

0x80110814: { "code": "COMADMIN_E_CANTMAKEINPROCSERVICE", "message":"Library applications cannot be Windows NT services."},

0x80110815: { "code": "COMADMIN_E_PROGIDINUSEBYCLSID", "message":"The ProgID provided to the copy operation is invalid. The ProgID is in use by another registered CLSID."},

0x80110816: { "code": "COMADMIN_E_DEFAULT_PARTITION_NOT_IN_SET", "message":"The partition specified as the default is not a member of the partition set."},

0x80110817: { "code": "COMADMIN_E_RECYCLEDPROCESSMAYNOTBEPAUSED", "message":"A recycled process cannot be paused."},

0x80110818: { "code": "COMADMIN_E_PARTITION_ACCESSDENIED", "message":"Access to the specified partition is denied."},

0x80110819: { "code": "COMADMIN_E_PARTITION_MSI_ONLY", "message":"Only application files (*.msi files) can be installed into partitions."},

0x8011081A: { "code": "COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_1_0_FORMAT", "message":"Applications containing one or more legacy components cannot be exported to 1.0 format."},

0x8011081B: { "code": "COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_NONBASE_PARTITIONS", "message":"Legacy components cannot exist in nonbase partitions."},

0x8011081C: { "code": "COMADMIN_E_COMP_MOVE_SOURCE", "message":"A component cannot be moved (or copied) from the System Application, an application proxy, or a nonchangeable application."},

0x8011081D: { "code": "COMADMIN_E_COMP_MOVE_DEST", "message":"A component cannot be moved (or copied) to the System Application, an application proxy or a nonchangeable application."},

0x8011081E: { "code": "COMADMIN_E_COMP_MOVE_PRIVATE", "message":"A private component cannot be moved (or copied) to a library application or to the base partition."},

0x8011081F: { "code": "COMADMIN_E_BASEPARTITION_REQUIRED_IN_SET", "message":"The Base Application Partition exists in all partition sets and cannot be removed."},

0x80110820: { "code": "COMADMIN_E_CANNOT_ALIAS_EVENTCLASS", "message":"Alas, Event Class components cannot be aliased."},

0x80110821: { "code": "COMADMIN_E_PRIVATE_ACCESSDENIED", "message":"Access is denied because the component is private."},

0x80110822: { "code": "COMADMIN_E_SAFERINVALID", "message":"The specified SAFER level is invalid."},

0x80110823: { "code": "COMADMIN_E_REGISTRY_ACCESSDENIED", "message":"The specified user cannot write to the system registry."},

0x80110824: { "code": "COMADMIN_E_PARTITIONS_DISABLED", "message":"COM+ partitions are currently disabled."},

0x801F0001: { "code": "ERROR_FLT_NO_HANDLER_DEFINED", "message":"A handler was not defined by the filter for this operation."},

0x801F0002: { "code": "ERROR_FLT_CONTEXT_ALREADY_DEFINED", "message":"A context is already defined for this object."},

0x801F0003: { "code": "ERROR_FLT_INVALID_ASYNCHRONOUS_REQUEST", "message":"Asynchronous requests are not valid for this operation."},

0x801F0004: { "code": "ERROR_FLT_DISALLOW_FAST_IO", "message":"Disallow the Fast IO path for this operation."},

0x801F0005: { "code": "ERROR_FLT_INVALID_NAME_REQUEST", "message":"An invalid name request was made. The name requested cannot be retrieved at this time."},

0x801F0006: { "code": "ERROR_FLT_NOT_SAFE_TO_POST_OPERATION", "message":"Posting this operation to a worker thread for further processing is not safe at this time because it could lead to a system deadlock."},

0x801F0007: { "code": "ERROR_FLT_NOT_INITIALIZED", "message":"The Filter Manager was not initialized when a filter tried to register. Be sure that the Filter Manager is being loaded as a driver."},

0x801F0008: { "code": "ERROR_FLT_FILTER_NOT_READY", "message":"The filter is not ready for attachment to volumes because it has not finished initializing (FltStartFiltering has not been called)."},

0x801F0009: { "code": "ERROR_FLT_POST_OPERATION_CLEANUP", "message":"The filter must clean up any operation-specific context at this time because it is being removed from the system before the operation is completed by the lower drivers."},

0x801F000A: { "code": "ERROR_FLT_INTERNAL_ERROR", "message":"The Filter Manager had an internal error from which it cannot recover; therefore, the operation has been failed. This is usually the result of a filter returning an invalid value from a preoperation callback."},

0x801F000B: { "code": "ERROR_FLT_DELETING_OBJECT", "message":"The object specified for this action is in the process of being deleted; therefore, the action requested cannot be completed at this time."},

0x801F000C: { "code": "ERROR_FLT_MUST_BE_NONPAGED_POOL", "message":"Nonpaged pool must be used for this type of context."},

0x801F000D: { "code": "ERROR_FLT_DUPLICATE_ENTRY", "message":"A duplicate handler definition has been provided for an operation."},

0x801F000E: { "code": "ERROR_FLT_CBDQ_DISABLED", "message":"The callback data queue has been disabled."},

0x801F000F: { "code": "ERROR_FLT_DO_NOT_ATTACH", "message":"Do not attach the filter to the volume at this time."},

0x801F0010: { "code": "ERROR_FLT_DO_NOT_DETACH", "message":"Do not detach the filter from the volume at this time."},

0x801F0011: { "code": "ERROR_FLT_INSTANCE_ALTITUDE_COLLISION", "message":"An instance already exists at this altitude on the volume specified."},

0x801F0012: { "code": "ERROR_FLT_INSTANCE_NAME_COLLISION", "message":"An instance already exists with this name on the volume specified."},

0x801F0013: { "code": "ERROR_FLT_FILTER_NOT_FOUND", "message":"The system could not find the filter specified."},

0x801F0014: { "code": "ERROR_FLT_VOLUME_NOT_FOUND", "message":"The system could not find the volume specified."},

0x801F0015: { "code": "ERROR_FLT_INSTANCE_NOT_FOUND", "message":"The system could not find the instance specified."},

0x801F0016: { "code": "ERROR_FLT_CONTEXT_ALLOCATION_NOT_FOUND", "message":"No registered context allocation definition was found for the given request."},

0x801F0017: { "code": "ERROR_FLT_INVALID_CONTEXT_REGISTRATION", "message":"An invalid parameter was specified during context registration."},

0x801F0018: { "code": "ERROR_FLT_NAME_CACHE_MISS", "message":"The name requested was not found in the Filter Manager name cache and could not be retrieved from the file system."},

0x801F0019: { "code": "ERROR_FLT_NO_DEVICE_OBJECT", "message":"The requested device object does not exist for the given volume."},

0x801F001A: { "code": "ERROR_FLT_VOLUME_ALREADY_MOUNTED", "message":"The specified volume is already mounted."},

0x801F001B: { "code": "ERROR_FLT_ALREADY_ENLISTED", "message":"The specified Transaction Context is already enlisted in a transaction."},

0x801F001C: { "code": "ERROR_FLT_CONTEXT_ALREADY_LINKED", "message":"The specified context is already attached to another object."},

0x801F0020: { "code": "ERROR_FLT_NO_WAITER_FOR_REPLY", "message":"No waiter is present for the filter's reply to this message."},

0x80260001: { "code": "ERROR_HUNG_DISPLAY_DRIVER_THREAD", "message":"{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the machine a dialog will be displayed giving you a chance to report this failure to Microsoft."},

0x80261001: { "code": "ERROR_MONITOR_NO_DESCRIPTOR", "message":"Monitor descriptor could not be obtained."},

0x80261002: { "code": "ERROR_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT", "message":"Format of the obtained monitor descriptor is not supported by this release."},

0x80263001: { "code": "DWM_E_COMPOSITIONDISABLED", "message":"{Desktop Composition is Disabled} The operation could not be completed because desktop composition is disabled."},

0x80263002: { "code": "DWM_E_REMOTING_NOT_SUPPORTED", "message":"{Some Desktop Composition APIs Are Not Supported While Remoting} Some desktop composition APIs are not supported while remoting. The operation is not supported while running in a remote session."},

0x80263003: { "code": "DWM_E_NO_REDIRECTION_SURFACE_AVAILABLE", "message":"{No DWM Redirection Surface is Available} The Desktop Window Manager (DWM) was unable to provide a redirection surface to complete the DirectX present."},

0x80263004: { "code": "DWM_E_NOT_QUEUING_PRESENTS", "message":"{DWM Is Not Queuing Presents for the Specified Window} The window specified is not currently using queued presents."},

0x80280000: { "code": "TPM_E_ERROR_MASK", "message":"This is an error mask to convert Trusted Platform Module (TPM) hardware errors to Win32 errors."},

0x80280001: { "code": "TPM_E_AUTHFAIL", "message":"Authentication failed."},

0x80280002: { "code": "TPM_E_BADINDEX", "message":"The index to a Platform Configuration Register (PCR), DIR, or other register is incorrect."},

0x80280003: { "code": "TPM_E_BAD_PARAMETER", "message":"One or more parameters are bad."},

0x80280004: { "code": "TPM_E_AUDITFAILURE", "message":"An operation completed successfully but the auditing of that operation failed."},

0x80280005: { "code": "TPM_E_CLEAR_DISABLED", "message":"The clear disable flag is set and all clear operations now require physical access."},

0x80280006: { "code": "TPM_E_DEACTIVATED", "message":"The TPM is deactivated."},

0x80280007: { "code": "TPM_E_DISABLED", "message":"The TPM is disabled."},

0x80280008: { "code": "TPM_E_DISABLED_CMD", "message":"The target command has been disabled."},

0x80280009: { "code": "TPM_E_FAIL", "message":"The operation failed."},

0x8028000A: { "code": "TPM_E_BAD_ORDINAL", "message":"The ordinal was unknown or inconsistent."},

0x8028000B: { "code": "TPM_E_INSTALL_DISABLED", "message":"The ability to install an owner is disabled."},

0x8028000C: { "code": "TPM_E_INVALID_KEYHANDLE", "message":"The key handle cannot be interpreted."},

0x8028000D: { "code": "TPM_E_KEYNOTFOUND", "message":"The key handle points to an invalid key."},

0x8028000E: { "code": "TPM_E_INAPPROPRIATE_ENC", "message":"Unacceptable encryption scheme."},

0x8028000F: { "code": "TPM_E_MIGRATEFAIL", "message":"Migration authorization failed."},

0x80280010: { "code": "TPM_E_INVALID_PCR_INFO", "message":"PCR information could not be interpreted."},

0x80280011: { "code": "TPM_E_NOSPACE", "message":"No room to load key."},

0x80280012: { "code": "TPM_E_NOSRK", "message":"There is no storage root key (SRK) set."},

0x80280013: { "code": "TPM_E_NOTSEALED_BLOB", "message":"An encrypted blob is invalid or was not created by this TPM."},

0x80280014: { "code": "TPM_E_OWNER_SET", "message":"There is already an owner."},

0x80280015: { "code": "TPM_E_RESOURCES", "message":"The TPM has insufficient internal resources to perform the requested action."},

0x80280016: { "code": "TPM_E_SHORTRANDOM", "message":"A random string was too short."},

0x80280017: { "code": "TPM_E_SIZE", "message":"The TPM does not have the space to perform the operation."},

0x80280018: { "code": "TPM_E_WRONGPCRVAL", "message":"The named PCR value does not match the current PCR value."},

0x80280019: { "code": "TPM_E_BAD_PARAM_SIZE", "message":"The paramSize argument to the command has the incorrect value."},

0x8028001A: { "code": "TPM_E_SHA_THREAD", "message":"There is no existing SHA-1 thread."},

0x8028001B: { "code": "TPM_E_SHA_ERROR", "message":"The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error."},

0x8028001C: { "code": "TPM_E_FAILEDSELFTEST", "message":"Self-test has failed and the TPM has shut down."},

0x8028001D: { "code": "TPM_E_AUTH2FAIL", "message":"The authorization for the second key in a two-key function failed authorization."},

0x8028001E: { "code": "TPM_E_BADTAG", "message":"The tag value sent to for a command is invalid."},

0x8028001F: { "code": "TPM_E_IOERROR", "message":"An I/O error occurred transmitting information to the TPM."},

0x80280020: { "code": "TPM_E_ENCRYPT_ERROR", "message":"The encryption process had a problem."},

0x80280021: { "code": "TPM_E_DECRYPT_ERROR", "message":"The decryption process did not complete."},

0x80280022: { "code": "TPM_E_INVALID_AUTHHANDLE", "message":"An invalid handle was used."},

0x80280023: { "code": "TPM_E_NO_ENDORSEMENT", "message":"The TPM does not have an endorsement key (EK) installed."},

0x80280024: { "code": "TPM_E_INVALID_KEYUSAGE", "message":"The usage of a key is not allowed."},

0x80280025: { "code": "TPM_E_WRONG_ENTITYTYPE", "message":"The submitted entity type is not allowed."},

0x80280026: { "code": "TPM_E_INVALID_POSTINIT", "message":"The command was received in the wrong sequence relative to TPM_Init and a subsequent TPM_Startup."},

0x80280027: { "code": "TPM_E_INAPPROPRIATE_SIG", "message":"Signed data cannot include additional DER information."},

0x80280028: { "code": "TPM_E_BAD_KEY_PROPERTY", "message":"The key properties in TPM_KEY_PARMs are not supported by this TPM."},

0x80280029: { "code": "TPM_E_BAD_MIGRATION", "message":"The migration properties of this key are incorrect."},

0x8028002A: { "code": "TPM_E_BAD_SCHEME", "message":"The signature or encryption scheme for this key is incorrect or not permitted in this situation."},

0x8028002B: { "code": "TPM_E_BAD_DATASIZE", "message":"The size of the data (or blob) parameter is bad or inconsistent with the referenced key."},

0x8028002C: { "code": "TPM_E_BAD_MODE", "message":"A mode parameter is bad, such as capArea or subCapArea for TPM_GetCapability, physicalPresence parameter for TPM_PhysicalPresence, or migrationType for TPM_CreateMigrationBlob."},

0x8028002D: { "code": "TPM_E_BAD_PRESENCE", "message":"Either the physicalPresence or physicalPresenceLock bits have the wrong value."},

0x8028002E: { "code": "TPM_E_BAD_VERSION", "message":"The TPM cannot perform this version of the capability."},

0x8028002F: { "code": "TPM_E_NO_WRAP_TRANSPORT", "message":"The TPM does not allow for wrapped transport sessions."},

0x80280030: { "code": "TPM_E_AUDITFAIL_UNSUCCESSFUL", "message":"TPM audit construction failed and the underlying command was returning a failure code also."},

0x80280031: { "code": "TPM_E_AUDITFAIL_SUCCESSFUL", "message":"TPM audit construction failed and the underlying command was returning success."},

0x80280032: { "code": "TPM_E_NOTRESETABLE", "message":"Attempt to reset a PCR that does not have the resettable attribute."},

0x80280033: { "code": "TPM_E_NOTLOCAL", "message":"Attempt to reset a PCR register that requires locality and the locality modifier not part of command transport."},

0x80280034: { "code": "TPM_E_BAD_TYPE", "message":"Make identity blob not properly typed."},

0x80280035: { "code": "TPM_E_INVALID_RESOURCE", "message":"When saving context identified resource type does not match actual resource."},

0x80280036: { "code": "TPM_E_NOTFIPS", "message":"The TPM is attempting to execute a command only available when in Federal Information Processing Standards (FIPS) mode."},

0x80280037: { "code": "TPM_E_INVALID_FAMILY", "message":"The command is attempting to use an invalid family ID."},

0x80280038: { "code": "TPM_E_NO_NV_PERMISSION", "message":"The permission to manipulate the NV storage is not available."},

0x80280039: { "code": "TPM_E_REQUIRES_SIGN", "message":"The operation requires a signed command."},

0x8028003A: { "code": "TPM_E_KEY_NOTSUPPORTED", "message":"Wrong operation to load an NV key."},

0x8028003B: { "code": "TPM_E_AUTH_CONFLICT", "message":"NV_LoadKey blob requires both owner and blob authorization."},

0x8028003C: { "code": "TPM_E_AREA_LOCKED", "message":"The NV area is locked and not writable."},

0x8028003D: { "code": "TPM_E_BAD_LOCALITY", "message":"The locality is incorrect for the attempted operation."},

0x8028003E: { "code": "TPM_E_READ_ONLY", "message":"The NV area is read-only and cannot be written to."},

0x8028003F: { "code": "TPM_E_PER_NOWRITE", "message":"There is no protection on the write to the NV area."},

0x80280040: { "code": "TPM_E_FAMILYCOUNT", "message":"The family count value does not match."},

0x80280041: { "code": "TPM_E_WRITE_LOCKED", "message":"The NV area has already been written to."},

0x80280042: { "code": "TPM_E_BAD_ATTRIBUTES", "message":"The NV area attributes conflict."},

0x80280043: { "code": "TPM_E_INVALID_STRUCTURE", "message":"The structure tag and version are invalid or inconsistent."},

0x80280044: { "code": "TPM_E_KEY_OWNER_CONTROL", "message":"The key is under control of the TPM owner and can only be evicted by the TPM owner."},

0x80280045: { "code": "TPM_E_BAD_COUNTER", "message":"The counter handle is incorrect."},

0x80280046: { "code": "TPM_E_NOT_FULLWRITE", "message":"The write is not a complete write of the area."},

0x80280047: { "code": "TPM_E_CONTEXT_GAP", "message":"The gap between saved context counts is too large."},

0x80280048: { "code": "TPM_E_MAXNVWRITES", "message":"The maximum number of NV writes without an owner has been exceeded."},

0x80280049: { "code": "TPM_E_NOOPERATOR", "message":"No operator AuthData value is set."},

0x8028004A: { "code": "TPM_E_RESOURCEMISSING", "message":"The resource pointed to by context is not loaded."},

0x8028004B: { "code": "TPM_E_DELEGATE_LOCK", "message":"The delegate administration is locked."},

0x8028004C: { "code": "TPM_E_DELEGATE_FAMILY", "message":"Attempt to manage a family other then the delegated family."},

0x8028004D: { "code": "TPM_E_DELEGATE_ADMIN", "message":"Delegation table management not enabled."},

0x8028004E: { "code": "TPM_E_TRANSPORT_NOTEXCLUSIVE", "message":"There was a command executed outside an exclusive transport session."},

0x8028004F: { "code": "TPM_E_OWNER_CONTROL", "message":"Attempt to context save an owner evict controlled key."},

0x80280050: { "code": "TPM_E_DAA_RESOURCES", "message":"The DAA command has no resources available to execute the command."},

0x80280051: { "code": "TPM_E_DAA_INPUT_DATA0", "message":"The consistency check on DAA parameter inputData0 has failed."},

0x80280052: { "code": "TPM_E_DAA_INPUT_DATA1", "message":"The consistency check on DAA parameter inputData1 has failed."},

0x80280053: { "code": "TPM_E_DAA_ISSUER_SETTINGS", "message":"The consistency check on DAA_issuerSettings has failed."},

0x80280054: { "code": "TPM_E_DAA_TPM_SETTINGS", "message":"The consistency check on DAA_tpmSpecific has failed."},

0x80280055: { "code": "TPM_E_DAA_STAGE", "message":"The atomic process indicated by the submitted DAA command is not the expected process."},

0x80280056: { "code": "TPM_E_DAA_ISSUER_VALIDITY", "message":"The issuer's validity check has detected an inconsistency."},

0x80280057: { "code": "TPM_E_DAA_WRONG_W", "message":"The consistency check on w has failed."},

0x80280058: { "code": "TPM_E_BAD_HANDLE", "message":"The handle is incorrect."},

0x80280059: { "code": "TPM_E_BAD_DELEGATE", "message":"Delegation is not correct."},

0x8028005A: { "code": "TPM_E_BADCONTEXT", "message":"The context blob is invalid."},

0x8028005B: { "code": "TPM_E_TOOMANYCONTEXTS", "message":"Too many contexts held by the TPM."},

0x8028005C: { "code": "TPM_E_MA_TICKET_SIGNATURE", "message":"Migration authority signature validation failure."},

0x8028005D: { "code": "TPM_E_MA_DESTINATION", "message":"Migration destination not authenticated."},

0x8028005E: { "code": "TPM_E_MA_SOURCE", "message":"Migration source incorrect."},

0x8028005F: { "code": "TPM_E_MA_AUTHORITY", "message":"Incorrect migration authority."},

0x80280061: { "code": "TPM_E_PERMANENTEK", "message":"Attempt to revoke the EK and the EK is not revocable."},

0x80280062: { "code": "TPM_E_BAD_SIGNATURE", "message":"Bad signature of CMK ticket."},

0x80280063: { "code": "TPM_E_NOCONTEXTSPACE", "message":"There is no room in the context list for additional contexts."},

0x80280400: { "code": "TPM_E_COMMAND_BLOCKED", "message":"The command was blocked."},

0x80280401: { "code": "TPM_E_INVALID_HANDLE", "message":"The specified handle was not found."},

0x80280402: { "code": "TPM_E_DUPLICATE_VHANDLE", "message":"The TPM returned a duplicate handle and the command needs to be resubmitted."},

0x80280403: { "code": "TPM_E_EMBEDDED_COMMAND_BLOCKED", "message":"The command within the transport was blocked."},

0x80280404: { "code": "TPM_E_EMBEDDED_COMMAND_UNSUPPORTED", "message":"The command within the transport is not supported."},

0x80280800: { "code": "TPM_E_RETRY", "message":"The TPM is too busy to respond to the command immediately, but the command could be resubmitted at a later time."},

0x80280801: { "code": "TPM_E_NEEDS_SELFTEST", "message":"SelfTestFull has not been run."},

0x80280802: { "code": "TPM_E_DOING_SELFTEST", "message":"The TPM is currently executing a full self-test."},

0x80280803: { "code": "TPM_E_DEFEND_LOCK_RUNNING", "message":"The TPM is defending against dictionary attacks and is in a time-out period."},

0x80284001: { "code": "TBS_E_INTERNAL_ERROR", "message":"An internal software error has been detected."},

0x80284002: { "code": "TBS_E_BAD_PARAMETER", "message":"One or more input parameters are bad."},

0x80284003: { "code": "TBS_E_INVALID_OUTPUT_POINTER", "message":"A specified output pointer is bad."},

0x80284004: { "code": "TBS_E_INVALID_CONTEXT", "message":"The specified context handle does not refer to a valid context."},

0x80284005: { "code": "TBS_E_INSUFFICIENT_BUFFER", "message":"A specified output buffer is too small."},

0x80284006: { "code": "TBS_E_IOERROR", "message":"An error occurred while communicating with the TPM."},

0x80284007: { "code": "TBS_E_INVALID_CONTEXT_PARAM", "message":"One or more context parameters are invalid."},

0x80284008: { "code": "TBS_E_SERVICE_NOT_RUNNING", "message":"The TPM Base Services (TBS) is not running and could not be started."},

0x80284009: { "code": "TBS_E_TOO_MANY_TBS_CONTEXTS", "message":"A new context could not be created because there are too many open contexts."},

0x8028400A: { "code": "TBS_E_TOO_MANY_RESOURCES", "message":"A new virtual resource could not be created because there are too many open virtual resources."},

0x8028400B: { "code": "TBS_E_SERVICE_START_PENDING", "message":"The TBS service has been started but is not yet running."},

0x8028400C: { "code": "TBS_E_PPI_NOT_SUPPORTED", "message":"The physical presence interface is not supported."},

0x8028400D: { "code": "TBS_E_COMMAND_CANCELED", "message":"The command was canceled."},

0x8028400E: { "code": "TBS_E_BUFFER_TOO_LARGE", "message":"The input or output buffer is too large."},

0x80290100: { "code": "TPMAPI_E_INVALID_STATE", "message":"The command buffer is not in the correct state."},

0x80290101: { "code": "TPMAPI_E_NOT_ENOUGH_DATA", "message":"The command buffer does not contain enough data to satisfy the request."},

0x80290102: { "code": "TPMAPI_E_TOO_MUCH_DATA", "message":"The command buffer cannot contain any more data."},

0x80290103: { "code": "TPMAPI_E_INVALID_OUTPUT_POINTER", "message":"One or more output parameters was null or invalid."},

0x80290104: { "code": "TPMAPI_E_INVALID_PARAMETER", "message":"One or more input parameters are invalid."},

0x80290105: { "code": "TPMAPI_E_OUT_OF_MEMORY", "message":"Not enough memory was available to satisfy the request."},

0x80290106: { "code": "TPMAPI_E_BUFFER_TOO_SMALL", "message":"The specified buffer was too small."},

0x80290107: { "code": "TPMAPI_E_INTERNAL_ERROR", "message":"An internal error was detected."},

0x80290108: { "code": "TPMAPI_E_ACCESS_DENIED", "message":"The caller does not have the appropriate rights to perform the requested operation."},

0x80290109: { "code": "TPMAPI_E_AUTHORIZATION_FAILED", "message":"The specified authorization information was invalid."},

0x8029010A: { "code": "TPMAPI_E_INVALID_CONTEXT_HANDLE", "message":"The specified context handle was not valid."},

0x8029010B: { "code": "TPMAPI_E_TBS_COMMUNICATION_ERROR", "message":"An error occurred while communicating with the TBS."},

0x8029010C: { "code": "TPMAPI_E_TPM_COMMAND_ERROR", "message":"The TPM returned an unexpected result."},

0x8029010D: { "code": "TPMAPI_E_MESSAGE_TOO_LARGE", "message":"The message was too large for the encoding scheme."},

0x8029010E: { "code": "TPMAPI_E_INVALID_ENCODING", "message":"The encoding in the binary large object (BLOB) was not recognized."},

0x8029010F: { "code": "TPMAPI_E_INVALID_KEY_SIZE", "message":"The key size is not valid."},

0x80290110: { "code": "TPMAPI_E_ENCRYPTION_FAILED", "message":"The encryption operation failed."},

0x80290111: { "code": "TPMAPI_E_INVALID_KEY_PARAMS", "message":"The key parameters structure was not valid."},

0x80290112: { "code": "TPMAPI_E_INVALID_MIGRATION_AUTHORIZATION_BLOB", "message":"The requested supplied data does not appear to be a valid migration authorization BLOB."},

0x80290113: { "code": "TPMAPI_E_INVALID_PCR_INDEX", "message":"The specified PCR index was invalid."},

0x80290114: { "code": "TPMAPI_E_INVALID_DELEGATE_BLOB", "message":"The data given does not appear to be a valid delegate BLOB."},

0x80290115: { "code": "TPMAPI_E_INVALID_CONTEXT_PARAMS", "message":"One or more of the specified context parameters was not valid."},

0x80290116: { "code": "TPMAPI_E_INVALID_KEY_BLOB", "message":"The data given does not appear to be a valid key BLOB."},

0x80290117: { "code": "TPMAPI_E_INVALID_PCR_DATA", "message":"The specified PCR data was invalid."},

0x80290118: { "code": "TPMAPI_E_INVALID_OWNER_AUTH", "message":"The format of the owner authorization data was invalid."},

0x80290200: { "code": "TBSIMP_E_BUFFER_TOO_SMALL", "message":"The specified buffer was too small."},

0x80290201: { "code": "TBSIMP_E_CLEANUP_FAILED", "message":"The context could not be cleaned up."},

0x80290202: { "code": "TBSIMP_E_INVALID_CONTEXT_HANDLE", "message":"The specified context handle is invalid."},

0x80290203: { "code": "TBSIMP_E_INVALID_CONTEXT_PARAM", "message":"An invalid context parameter was specified."},

0x80290204: { "code": "TBSIMP_E_TPM_ERROR", "message":"An error occurred while communicating with the TPM."},

0x80290205: { "code": "TBSIMP_E_HASH_BAD_KEY", "message":"No entry with the specified key was found."},

0x80290206: { "code": "TBSIMP_E_DUPLICATE_VHANDLE", "message":"The specified virtual handle matches a virtual handle already in use."},

0x80290207: { "code": "TBSIMP_E_INVALID_OUTPUT_POINTER", "message":"The pointer to the returned handle location was null or invalid."},

0x80290208: { "code": "TBSIMP_E_INVALID_PARAMETER", "message":"One or more parameters are invalid."},

0x80290209: { "code": "TBSIMP_E_RPC_INIT_FAILED", "message":"The RPC subsystem could not be initialized."},

0x8029020A: { "code": "TBSIMP_E_SCHEDULER_NOT_RUNNING", "message":"The TBS scheduler is not running."},

0x8029020B: { "code": "TBSIMP_E_COMMAND_CANCELED", "message":"The command was canceled."},

0x8029020C: { "code": "TBSIMP_E_OUT_OF_MEMORY", "message":"There was not enough memory to fulfill the request."},

0x8029020D: { "code": "TBSIMP_E_LIST_NO_MORE_ITEMS", "message":"The specified list is empty, or the iteration has reached the end of the list."},

0x8029020E: { "code": "TBSIMP_E_LIST_NOT_FOUND", "message":"The specified item was not found in the list."},

0x8029020F: { "code": "TBSIMP_E_NOT_ENOUGH_SPACE", "message":"The TPM does not have enough space to load the requested resource."},

0x80290210: { "code": "TBSIMP_E_NOT_ENOUGH_TPM_CONTEXTS", "message":"There are too many TPM contexts in use."},

0x80290211: { "code": "TBSIMP_E_COMMAND_FAILED", "message":"The TPM command failed."},

0x80290212: { "code": "TBSIMP_E_UNKNOWN_ORDINAL", "message":"The TBS does not recognize the specified ordinal."},

0x80290213: { "code": "TBSIMP_E_RESOURCE_EXPIRED", "message":"The requested resource is no longer available."},

0x80290214: { "code": "TBSIMP_E_INVALID_RESOURCE", "message":"The resource type did not match."},

0x80290215: { "code": "TBSIMP_E_NOTHING_TO_UNLOAD", "message":"No resources can be unloaded."},

0x80290216: { "code": "TBSIMP_E_HASH_TABLE_FULL", "message":"No new entries can be added to the hash table."},

0x80290217: { "code": "TBSIMP_E_TOO_MANY_TBS_CONTEXTS", "message":"A new TBS context could not be created because there are too many open contexts."},

0x80290218: { "code": "TBSIMP_E_TOO_MANY_RESOURCES", "message":"A new virtual resource could not be created because there are too many open virtual resources."},

0x80290219: { "code": "TBSIMP_E_PPI_NOT_SUPPORTED", "message":"The physical presence interface is not supported."},

0x8029021A: { "code": "TBSIMP_E_TPM_INCOMPATIBLE", "message":"TBS is not compatible with the version of TPM found on the system."},

0x80290300: { "code": "TPM_E_PPI_ACPI_FAILURE", "message":"A general error was detected when attempting to acquire the BIOS response to a physical presence command."},

0x80290301: { "code": "TPM_E_PPI_USER_ABORT", "message":"The user failed to confirm the TPM operation request."},

0x80290302: { "code": "TPM_E_PPI_BIOS_FAILURE", "message":"The BIOS failure prevented the successful execution of the requested TPM operation (for example, invalid TPM operation request, BIOS communication error with the TPM)."},

0x80290303: { "code": "TPM_E_PPI_NOT_SUPPORTED", "message":"The BIOS does not support the physical presence interface."},

0x80300002: { "code": "PLA_E_DCS_NOT_FOUND", "message":"A Data Collector Set was not found."},

0x80300045: { "code": "PLA_E_TOO_MANY_FOLDERS", "message":"Unable to start Data Collector Set because there are too many folders."},

0x80300070: { "code": "PLA_E_NO_MIN_DISK", "message":"Not enough free disk space to start Data Collector Set."},

0x803000AA: { "code": "PLA_E_DCS_IN_USE", "message":"Data Collector Set is in use."},

0x803000B7: { "code": "PLA_E_DCS_ALREADY_EXISTS", "message":"Data Collector Set already exists."},

0x80300101: { "code": "PLA_E_PROPERTY_CONFLICT", "message":"Property value conflict."},

0x80300102: { "code": "PLA_E_DCS_SINGLETON_REQUIRED", "message":"The current configuration for this Data Collector Set requires that it contain exactly one Data Collector."},

0x80300103: { "code": "PLA_E_CREDENTIALS_REQUIRED", "message":"A user account is required to commit the current Data Collector Set properties."},

0x80300104: { "code": "PLA_E_DCS_NOT_RUNNING", "message":"Data Collector Set is not running."},

0x80300105: { "code": "PLA_E_CONFLICT_INCL_EXCL_API", "message":"A conflict was detected in the list of include and exclude APIs. Do not specify the same API in both the include list and the exclude list."},

0x80300106: { "code": "PLA_E_NETWORK_EXE_NOT_VALID", "message":"The executable path specified refers to a network share or UNC path."},

0x80300107: { "code": "PLA_E_EXE_ALREADY_CONFIGURED", "message":"The executable path specified is already configured for API tracing."},

0x80300108: { "code": "PLA_E_EXE_PATH_NOT_VALID", "message":"The executable path specified does not exist. Verify that the specified path is correct."},

0x80300109: { "code": "PLA_E_DC_ALREADY_EXISTS", "message":"Data Collector already exists."},

0x8030010A: { "code": "PLA_E_DCS_START_WAIT_TIMEOUT", "message":"The wait for the Data Collector Set start notification has timed out."},

0x8030010B: { "code": "PLA_E_DC_START_WAIT_TIMEOUT", "message":"The wait for the Data Collector to start has timed out."},

0x8030010C: { "code": "PLA_E_REPORT_WAIT_TIMEOUT", "message":"The wait for the report generation tool to finish has timed out."},

0x8030010D: { "code": "PLA_E_NO_DUPLICATES", "message":"Duplicate items are not allowed."},

0x8030010E: { "code": "PLA_E_EXE_FULL_PATH_REQUIRED", "message":"When specifying the executable to trace, you must specify a full path to the executable and not just a file name."},

0x8030010F: { "code": "PLA_E_INVALID_SESSION_NAME", "message":"The session name provided is invalid."},

0x80300110: { "code": "PLA_E_PLA_CHANNEL_NOT_ENABLED", "message":"The Event Log channel Microsoft-Windows-Diagnosis-PLA/Operational must be enabled to perform this operation."},

0x80300111: { "code": "PLA_E_TASKSCHED_CHANNEL_NOT_ENABLED", "message":"The Event Log channel Microsoft-Windows-TaskScheduler must be enabled to perform this operation."},

0x80310000: { "code": "FVE_E_LOCKED_VOLUME", "message":"The volume must be unlocked before it can be used."},

0x80310001: { "code": "FVE_E_NOT_ENCRYPTED", "message":"The volume is fully decrypted and no key is available."},

0x80310002: { "code": "FVE_E_NO_TPM_BIOS", "message":"The firmware does not support using a TPM during boot."},

0x80310003: { "code": "FVE_E_NO_MBR_METRIC", "message":"The firmware does not use a TPM to perform initial program load (IPL) measurement."},

0x80310004: { "code": "FVE_E_NO_BOOTSECTOR_METRIC", "message":"The master boot record (MBR) is not TPM-aware."},

0x80310005: { "code": "FVE_E_NO_BOOTMGR_METRIC", "message":"The BOOTMGR is not being measured by the TPM."},

0x80310006: { "code": "FVE_E_WRONG_BOOTMGR", "message":"The BOOTMGR component does not perform expected TPM measurements."},

0x80310007: { "code": "FVE_E_SECURE_KEY_REQUIRED", "message":"No secure key protection mechanism has been defined."},

0x80310008: { "code": "FVE_E_NOT_ACTIVATED", "message":"This volume has not been provisioned for encryption."},

0x80310009: { "code": "FVE_E_ACTION_NOT_ALLOWED", "message":"Requested action was denied by the full-volume encryption (FVE) control engine."},

0x8031000A: { "code": "FVE_E_AD_SCHEMA_NOT_INSTALLED", "message":"The Active Directory forest does not contain the required attributes and classes to host FVE or TPM information."},

0x8031000B: { "code": "FVE_E_AD_INVALID_DATATYPE", "message":"The type of data obtained from Active Directory was not expected."},

0x8031000C: { "code": "FVE_E_AD_INVALID_DATASIZE", "message":"The size of the data obtained from Active Directory was not expected."},

0x8031000D: { "code": "FVE_E_AD_NO_VALUES", "message":"The attribute read from Active Directory has no (zero) values."},

0x8031000E: { "code": "FVE_E_AD_ATTR_NOT_SET", "message":"The attribute was not set."},

0x8031000F: { "code": "FVE_E_AD_GUID_NOT_FOUND", "message":"The specified GUID could not be found."},

0x80310010: { "code": "FVE_E_BAD_INFORMATION", "message":"The control block for the encrypted volume is not valid."},

0x80310011: { "code": "FVE_E_TOO_SMALL", "message":"Not enough free space remaining on volume to allow encryption."},

0x80310012: { "code": "FVE_E_SYSTEM_VOLUME", "message":"The volume cannot be encrypted because it is required to boot the operating system."},

0x80310013: { "code": "FVE_E_FAILED_WRONG_FS", "message":"The volume cannot be encrypted because the file system is not supported."},

0x80310014: { "code": "FVE_E_FAILED_BAD_FS", "message":"The file system is inconsistent. Run CHKDSK."},

0x80310015: { "code": "FVE_E_NOT_SUPPORTED", "message":"This volume cannot be encrypted."},

0x80310016: { "code": "FVE_E_BAD_DATA", "message":"Data supplied is malformed."},

0x80310017: { "code": "FVE_E_VOLUME_NOT_BOUND", "message":"Volume is not bound to the system."},

0x80310018: { "code": "FVE_E_TPM_NOT_OWNED", "message":"TPM must be owned before a volume can be bound to it."},

0x80310019: { "code": "FVE_E_NOT_DATA_VOLUME", "message":"The volume specified is not a data volume."},

0x8031001A: { "code": "FVE_E_AD_INSUFFICIENT_BUFFER", "message":"The buffer supplied to a function was insufficient to contain the returned data."},

0x8031001B: { "code": "FVE_E_CONV_READ", "message":"A read operation failed while converting the volume."},

0x8031001C: { "code": "FVE_E_CONV_WRITE", "message":"A write operation failed while converting the volume."},

0x8031001D: { "code": "FVE_E_KEY_REQUIRED", "message":"One or more key protection mechanisms are required for this volume."},

0x8031001E: { "code": "FVE_E_CLUSTERING_NOT_SUPPORTED", "message":"Cluster configurations are not supported."},

0x8031001F: { "code": "FVE_E_VOLUME_BOUND_ALREADY", "message":"The volume is already bound to the system."},

0x80310020: { "code": "FVE_E_OS_NOT_PROTECTED", "message":"The boot OS volume is not being protected via FVE."},

0x80310021: { "code": "FVE_E_PROTECTION_DISABLED", "message":"All protection mechanisms are effectively disabled (clear key exists)."},

0x80310022: { "code": "FVE_E_RECOVERY_KEY_REQUIRED", "message":"A recovery key protection mechanism is required."},

0x80310023: { "code": "FVE_E_FOREIGN_VOLUME", "message":"This volume cannot be bound to a TPM."},

0x80310024: { "code": "FVE_E_OVERLAPPED_UPDATE", "message":"The control block for the encrypted volume was updated by another thread. Try again."},

0x80310025: { "code": "FVE_E_TPM_SRK_AUTH_NOT_ZERO", "message":"The SRK authentication of the TPM is not zero and, therefore, is not compatible."},

0x80310026: { "code": "FVE_E_FAILED_SECTOR_SIZE", "message":"The volume encryption algorithm cannot be used on this sector size."},

0x80310027: { "code": "FVE_E_FAILED_AUTHENTICATION", "message":"BitLocker recovery authentication failed."},

0x80310028: { "code": "FVE_E_NOT_OS_VOLUME", "message":"The volume specified is not the boot OS volume."},

0x80310029: { "code": "FVE_E_AUTOUNLOCK_ENABLED", "message":"Auto-unlock information for data volumes is present on the boot OS volume."},

0x8031002A: { "code": "FVE_E_WRONG_BOOTSECTOR", "message":"The system partition boot sector does not perform TPM measurements."},

0x8031002B: { "code": "FVE_E_WRONG_SYSTEM_FS", "message":"The system partition file system must be NTFS."},

0x8031002C: { "code": "FVE_E_POLICY_PASSWORD_REQUIRED", "message":"Group policy requires a recovery password before encryption can begin."},

0x8031002D: { "code": "FVE_E_CANNOT_SET_FVEK_ENCRYPTED", "message":"The volume encryption algorithm and key cannot be set on an encrypted volume."},

0x8031002E: { "code": "FVE_E_CANNOT_ENCRYPT_NO_KEY", "message":"A key must be specified before encryption can begin."},

0x80310030: { "code": "FVE_E_BOOTABLE_CDDVD", "message":"A bootable CD/DVD is in the system. Remove the CD/DVD and reboot the system."},

0x80310031: { "code": "FVE_E_PROTECTOR_EXISTS", "message":"An instance of this key protector already exists on the volume."},

0x80310032: { "code": "FVE_E_RELATIVE_PATH", "message":"The file cannot be saved to a relative path."},

0x80320001: { "code": "FWP_E_CALLOUT_NOT_FOUND", "message":"The callout does not exist."},

0x80320002: { "code": "FWP_E_CONDITION_NOT_FOUND", "message":"The filter condition does not exist."},

0x80320003: { "code": "FWP_E_FILTER_NOT_FOUND", "message":"The filter does not exist."},

0x80320004: { "code": "FWP_E_LAYER_NOT_FOUND", "message":"The layer does not exist."},

0x80320005: { "code": "FWP_E_PROVIDER_NOT_FOUND", "message":"The provider does not exist."},

0x80320006: { "code": "FWP_E_PROVIDER_CONTEXT_NOT_FOUND", "message":"The provider context does not exist."},

0x80320007: { "code": "FWP_E_SUBLAYER_NOT_FOUND", "message":"The sublayer does not exist."},

0x80320008: { "code": "FWP_E_NOT_FOUND", "message":"The object does not exist."},

0x80320009: { "code": "FWP_E_ALREADY_EXISTS", "message":"An object with that GUID or LUID already exists."},

0x8032000A: { "code": "FWP_E_IN_USE", "message":"The object is referenced by other objects and, therefore, cannot be deleted."},

0x8032000B: { "code": "FWP_E_DYNAMIC_SESSION_IN_PROGRESS", "message":"The call is not allowed from within a dynamic session."},

0x8032000C: { "code": "FWP_E_WRONG_SESSION", "message":"The call was made from the wrong session and, therefore, cannot be completed."},

0x8032000D: { "code": "FWP_E_NO_TXN_IN_PROGRESS", "message":"The call must be made from within an explicit transaction."},

0x8032000E: { "code": "FWP_E_TXN_IN_PROGRESS", "message":"The call is not allowed from within an explicit transaction."},

0x8032000F: { "code": "FWP_E_TXN_ABORTED", "message":"The explicit transaction has been forcibly canceled."},

0x80320010: { "code": "FWP_E_SESSION_ABORTED", "message":"The session has been canceled."},

0x80320011: { "code": "FWP_E_INCOMPATIBLE_TXN", "message":"The call is not allowed from within a read-only transaction."},

0x80320012: { "code": "FWP_E_TIMEOUT", "message":"The call timed out while waiting to acquire the transaction lock."},

0x80320013: { "code": "FWP_E_NET_EVENTS_DISABLED", "message":"Collection of network diagnostic events is disabled."},

0x80320014: { "code": "FWP_E_INCOMPATIBLE_LAYER", "message":"The operation is not supported by the specified layer."},

0x80320015: { "code": "FWP_E_KM_CLIENTS_ONLY", "message":"The call is allowed for kernel-mode callers only."},

0x80320016: { "code": "FWP_E_LIFETIME_MISMATCH", "message":"The call tried to associate two objects with incompatible lifetimes."},

0x80320017: { "code": "FWP_E_BUILTIN_OBJECT", "message":"The object is built in and, therefore, cannot be deleted."},

0x80320018: { "code": "FWP_E_TOO_MANY_BOOTTIME_FILTERS", "message":"The maximum number of boot-time filters has been reached."},

0x80320019: { "code": "FWP_E_NOTIFICATION_DROPPED", "message":"A notification could not be delivered because a message queue is at its maximum capacity."},

0x8032001A: { "code": "FWP_E_TRAFFIC_MISMATCH", "message":"The traffic parameters do not match those for the security association context."},

0x8032001B: { "code": "FWP_E_INCOMPATIBLE_SA_STATE", "message":"The call is not allowed for the current security association state."},

0x8032001C: { "code": "FWP_E_NULL_POINTER", "message":"A required pointer is null."},

0x8032001D: { "code": "FWP_E_INVALID_ENUMERATOR", "message":"An enumerator is not valid."},

0x8032001E: { "code": "FWP_E_INVALID_FLAGS", "message":"The flags field contains an invalid value."},

0x8032001F: { "code": "FWP_E_INVALID_NET_MASK", "message":"A network mask is not valid."},

0x80320020: { "code": "FWP_E_INVALID_RANGE", "message":"An FWP_RANGE is not valid."},

0x80320021: { "code": "FWP_E_INVALID_INTERVAL", "message":"The time interval is not valid."},

0x80320022: { "code": "FWP_E_ZERO_LENGTH_ARRAY", "message":"An array that must contain at least one element that is zero-length."},

0x80320023: { "code": "FWP_E_NULL_DISPLAY_NAME", "message":"The displayData.name field cannot be null."},

0x80320024: { "code": "FWP_E_INVALID_ACTION_TYPE", "message":"The action type is not one of the allowed action types for a filter."},

0x80320025: { "code": "FWP_E_INVALID_WEIGHT", "message":"The filter weight is not valid."},

0x80320026: { "code": "FWP_E_MATCH_TYPE_MISMATCH", "message":"A filter condition contains a match type that is not compatible with the operands."},

0x80320027: { "code": "FWP_E_TYPE_MISMATCH", "message":"An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type."},

0x80320028: { "code": "FWP_E_OUT_OF_BOUNDS", "message":"An integer value is outside the allowed range."},

0x80320029: { "code": "FWP_E_RESERVED", "message":"A reserved field is nonzero."},

0x8032002A: { "code": "FWP_E_DUPLICATE_CONDITION", "message":"A filter cannot contain multiple conditions operating on a single field."},

0x8032002B: { "code": "FWP_E_DUPLICATE_KEYMOD", "message":"A policy cannot contain the same keying module more than once."},

0x8032002C: { "code": "FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER", "message":"The action type is not compatible with the layer."},

0x8032002D: { "code": "FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER", "message":"The action type is not compatible with the sublayer."},

0x8032002E: { "code": "FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER", "message":"The raw context or the provider context is not compatible with the layer."},

0x8032002F: { "code": "FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT", "message":"The raw context or the provider context is not compatible with the callout."},

0x80320030: { "code": "FWP_E_INCOMPATIBLE_AUTH_METHOD", "message":"The authentication method is not compatible with the policy type."},

0x80320031: { "code": "FWP_E_INCOMPATIBLE_DH_GROUP", "message":"The Diffie-Hellman group is not compatible with the policy type."},

0x80320032: { "code": "FWP_E_EM_NOT_SUPPORTED", "message":"An Internet Key Exchange (IKE) policy cannot contain an Extended Mode policy."},

0x80320033: { "code": "FWP_E_NEVER_MATCH", "message":"The enumeration template or subscription will never match any objects."},

0x80320034: { "code": "FWP_E_PROVIDER_CONTEXT_MISMATCH", "message":"The provider context is of the wrong type."},

0x80320035: { "code": "FWP_E_INVALID_PARAMETER", "message":"The parameter is incorrect."},

0x80320036: { "code": "FWP_E_TOO_MANY_SUBLAYERS", "message":"The maximum number of sublayers has been reached."},

0x80320037: { "code": "FWP_E_CALLOUT_NOTIFICATION_FAILED", "message":"The notification function for a callout returned an error."},

0x80320038: { "code": "FWP_E_INCOMPATIBLE_AUTH_CONFIG", "message":"The IPsec authentication configuration is not compatible with the authentication type."},

0x80320039: { "code": "FWP_E_INCOMPATIBLE_CIPHER_CONFIG", "message":"The IPsec cipher configuration is not compatible with the cipher type."},

0x80340002: { "code": "ERROR_NDIS_INTERFACE_CLOSING", "message":"The binding to the network interface is being closed."},

0x80340004: { "code": "ERROR_NDIS_BAD_VERSION", "message":"An invalid version was specified."},

0x80340005: { "code": "ERROR_NDIS_BAD_CHARACTERISTICS", "message":"An invalid characteristics table was used."},

0x80340006: { "code": "ERROR_NDIS_ADAPTER_NOT_FOUND", "message":"Failed to find the network interface, or the network interface is not ready."},

0x80340007: { "code": "ERROR_NDIS_OPEN_FAILED", "message":"Failed to open the network interface."},

0x80340008: { "code": "ERROR_NDIS_DEVICE_FAILED", "message":"The network interface has encountered an internal unrecoverable failure."},

0x80340009: { "code": "ERROR_NDIS_MULTICAST_FULL", "message":"The multicast list on the network interface is full."},

0x8034000A: { "code": "ERROR_NDIS_MULTICAST_EXISTS", "message":"An attempt was made to add a duplicate multicast address to the list."},

0x8034000B: { "code": "ERROR_NDIS_MULTICAST_NOT_FOUND", "message":"At attempt was made to remove a multicast address that was never added."},

0x8034000C: { "code": "ERROR_NDIS_REQUEST_ABORTED", "message":"The network interface aborted the request."},

0x8034000D: { "code": "ERROR_NDIS_RESET_IN_PROGRESS", "message":"The network interface cannot process the request because it is being reset."},

0x8034000F: { "code": "ERROR_NDIS_INVALID_PACKET", "message":"An attempt was made to send an invalid packet on a network interface."},

0x80340010: { "code": "ERROR_NDIS_INVALID_DEVICE_REQUEST", "message":"The specified request is not a valid operation for the target device."},

0x80340011: { "code": "ERROR_NDIS_ADAPTER_NOT_READY", "message":"The network interface is not ready to complete this operation."},

0x80340014: { "code": "ERROR_NDIS_INVALID_LENGTH", "message":"The length of the buffer submitted for this operation is not valid."},

0x80340015: { "code": "ERROR_NDIS_INVALID_DATA", "message":"The data used for this operation is not valid."},

0x80340016: { "code": "ERROR_NDIS_BUFFER_TOO_SHORT", "message":"The length of the buffer submitted for this operation is too small."},

0x80340017: { "code": "ERROR_NDIS_INVALID_OID", "message":"The network interface does not support this OID."},

0x80340018: { "code": "ERROR_NDIS_ADAPTER_REMOVED", "message":"The network interface has been removed."},

0x80340019: { "code": "ERROR_NDIS_UNSUPPORTED_MEDIA", "message":"The network interface does not support this media type."},

0x8034001A: { "code": "ERROR_NDIS_GROUP_ADDRESS_IN_USE", "message":"An attempt was made to remove a token ring group address that is in use by other components."},

0x8034001B: { "code": "ERROR_NDIS_FILE_NOT_FOUND", "message":"An attempt was made to map a file that cannot be found."},

0x8034001C: { "code": "ERROR_NDIS_ERROR_READING_FILE", "message":"An error occurred while the NDIS tried to map the file."},

0x8034001D: { "code": "ERROR_NDIS_ALREADY_MAPPED", "message":"An attempt was made to map a file that is already mapped."},

0x8034001E: { "code": "ERROR_NDIS_RESOURCE_CONFLICT", "message":"An attempt to allocate a hardware resource failed because the resource is used by another component."},

0x8034001F: { "code": "ERROR_NDIS_MEDIA_DISCONNECTED", "message":"The I/O operation failed because network media is disconnected or the wireless access point is out of range."},

0x80340022: { "code": "ERROR_NDIS_INVALID_ADDRESS", "message":"The network address used in the request is invalid."},

0x8034002A: { "code": "ERROR_NDIS_PAUSED", "message":"The offload operation on the network interface has been paused."},

0x8034002B: { "code": "ERROR_NDIS_INTERFACE_NOT_FOUND", "message":"The network interface was not found."},

0x8034002C: { "code": "ERROR_NDIS_UNSUPPORTED_REVISION", "message":"The revision number specified in the structure is not supported."},

0x8034002D: { "code": "ERROR_NDIS_INVALID_PORT", "message":"The specified port does not exist on this network interface."},

0x8034002E: { "code": "ERROR_NDIS_INVALID_PORT_STATE", "message":"The current state of the specified port on this network interface does not support the requested operation."},

0x803400BB: { "code": "ERROR_NDIS_NOT_SUPPORTED", "message":"The network interface does not support this request."},

0x80342000: { "code": "ERROR_NDIS_DOT11_AUTO_CONFIG_ENABLED", "message":"The wireless local area network (LAN) interface is in auto-configuration mode and does not support the requested parameter change operation."},

0x80342001: { "code": "ERROR_NDIS_DOT11_MEDIA_IN_USE", "message":"The wireless LAN interface is busy and cannot perform the requested operation."},

0x80342002: { "code": "ERROR_NDIS_DOT11_POWER_STATE_INVALID", "message":"The wireless LAN interface is shutting down and does not support the requested operation."},

0x8DEAD01B: { "code": "TRK_E_NOT_FOUND", "message":"A requested object was not found."},

0x8DEAD01C: { "code": "TRK_E_VOLUME_QUOTA_EXCEEDED", "message":"The server received a CREATE_VOLUME subrequest of a SYNC_VOLUMES request, but the ServerVolumeTable size limit for the RequestMachine has already been reached."},

0x8DEAD01E: { "code": "TRK_SERVER_TOO_BUSY", "message":"The server is busy, and the client should retry the request at a later time."},

0xC0090001: { "code": "ERROR_AUDITING_DISABLED", "message":"The specified event is currently not being audited."},

0xC0090002: { "code": "ERROR_ALL_SIDS_FILTERED", "message":"The SID filtering operation removed all SIDs."},

0xC0090003: { "code": "ERROR_BIZRULES_NOT_ENABLED", "message":"Business rule scripts are disabled for the calling application."},

0xC00D0005: { "code": "NS_E_NOCONNECTION", "message":"There is no connection established with the Windows Media server. The operation failed."},

0xC00D0006: { "code": "NS_E_CANNOTCONNECT", "message":"Unable to establish a connection to the server."},

0xC00D0007: { "code": "NS_E_CANNOTDESTROYTITLE", "message":"Unable to destroy the title."},

0xC00D0008: { "code": "NS_E_CANNOTRENAMETITLE", "message":"Unable to rename the title."},

0xC00D0009: { "code": "NS_E_CANNOTOFFLINEDISK", "message":"Unable to offline disk."},

0xC00D000A: { "code": "NS_E_CANNOTONLINEDISK", "message":"Unable to online disk."},

0xC00D000B: { "code": "NS_E_NOREGISTEREDWALKER", "message":"There is no file parser registered for this type of file."},

0xC00D000C: { "code": "NS_E_NOFUNNEL", "message":"There is no data connection established."},

0xC00D000D: { "code": "NS_E_NO_LOCALPLAY", "message":"Failed to load the local play DLL."},

0xC00D000E: { "code": "NS_E_NETWORK_BUSY", "message":"The network is busy."},

0xC00D000F: { "code": "NS_E_TOO_MANY_SESS", "message":"The server session limit was exceeded."},

0xC00D0010: { "code": "NS_E_ALREADY_CONNECTED", "message":"The network connection already exists."},

0xC00D0011: { "code": "NS_E_INVALID_INDEX", "message":"Index %1 is invalid."},

0xC00D0012: { "code": "NS_E_PROTOCOL_MISMATCH", "message":"There is no protocol or protocol version supported by both the client and the server."},

0xC00D0013: { "code": "NS_E_TIMEOUT", "message":"The server, a computer set up to offer multimedia content to other computers, could not handle your request for multimedia content in a timely manner. Please try again later."},

0xC00D0014: { "code": "NS_E_NET_WRITE", "message":"Error writing to the network."},

0xC00D0015: { "code": "NS_E_NET_READ", "message":"Error reading from the network."},

0xC00D0016: { "code": "NS_E_DISK_WRITE", "message":"Error writing to a disk."},

0xC00D0017: { "code": "NS_E_DISK_READ", "message":"Error reading from a disk."},

0xC00D0018: { "code": "NS_E_FILE_WRITE", "message":"Error writing to a file."},

0xC00D0019: { "code": "NS_E_FILE_READ", "message":"Error reading from a file."},

0xC00D001A: { "code": "NS_E_FILE_NOT_FOUND", "message":"The system cannot find the file specified."},

0xC00D001B: { "code": "NS_E_FILE_EXISTS", "message":"The file already exists."},

0xC00D001C: { "code": "NS_E_INVALID_NAME", "message":"The file name, directory name, or volume label syntax is incorrect."},

0xC00D001D: { "code": "NS_E_FILE_OPEN_FAILED", "message":"Failed to open a file."},

0xC00D001E: { "code": "NS_E_FILE_ALLOCATION_FAILED", "message":"Unable to allocate a file."},

0xC00D001F: { "code": "NS_E_FILE_INIT_FAILED", "message":"Unable to initialize a file."},

0xC00D0020: { "code": "NS_E_FILE_PLAY_FAILED", "message":"Unable to play a file."},

0xC00D0021: { "code": "NS_E_SET_DISK_UID_FAILED", "message":"Could not set the disk UID."},

0xC00D0022: { "code": "NS_E_INDUCED", "message":"An error was induced for testing purposes."},

0xC00D0023: { "code": "NS_E_CCLINK_DOWN", "message":"Two Content Servers failed to communicate."},

0xC00D0024: { "code": "NS_E_INTERNAL", "message":"An unknown error occurred."},

0xC00D0025: { "code": "NS_E_BUSY", "message":"The requested resource is in use."},

0xC00D0026: { "code": "NS_E_UNRECOGNIZED_STREAM_TYPE", "message":"The specified protocol is not recognized. Be sure that the file name and syntax, such as slashes, are correct for the protocol."},

0xC00D0027: { "code": "NS_E_NETWORK_SERVICE_FAILURE", "message":"The network service provider failed."},

0xC00D0028: { "code": "NS_E_NETWORK_RESOURCE_FAILURE", "message":"An attempt to acquire a network resource failed."},

0xC00D0029: { "code": "NS_E_CONNECTION_FAILURE", "message":"The network connection has failed."},

0xC00D002A: { "code": "NS_E_SHUTDOWN", "message":"The session is being terminated locally."},

0xC00D002B: { "code": "NS_E_INVALID_REQUEST", "message":"The request is invalid in the current state."},

0xC00D002C: { "code": "NS_E_INSUFFICIENT_BANDWIDTH", "message":"There is insufficient bandwidth available to fulfill the request."},

0xC00D002D: { "code": "NS_E_NOT_REBUILDING", "message":"The disk is not rebuilding."},

0xC00D002E: { "code": "NS_E_LATE_OPERATION", "message":"An operation requested for a particular time could not be carried out on schedule."},

0xC00D002F: { "code": "NS_E_INVALID_DATA", "message":"Invalid or corrupt data was encountered."},

0xC00D0030: { "code": "NS_E_FILE_BANDWIDTH_LIMIT", "message":"The bandwidth required to stream a file is higher than the maximum file bandwidth allowed on the server."},

0xC00D0031: { "code": "NS_E_OPEN_FILE_LIMIT", "message":"The client cannot have any more files open simultaneously."},

0xC00D0032: { "code": "NS_E_BAD_CONTROL_DATA", "message":"The server received invalid data from the client on the control connection."},

0xC00D0033: { "code": "NS_E_NO_STREAM", "message":"There is no stream available."},

0xC00D0034: { "code": "NS_E_STREAM_END", "message":"There is no more data in the stream."},

0xC00D0035: { "code": "NS_E_SERVER_NOT_FOUND", "message":"The specified server could not be found."},

0xC00D0036: { "code": "NS_E_DUPLICATE_NAME", "message":"The specified name is already in use."},

0xC00D0037: { "code": "NS_E_DUPLICATE_ADDRESS", "message":"The specified address is already in use."},

0xC00D0038: { "code": "NS_E_BAD_MULTICAST_ADDRESS", "message":"The specified address is not a valid multicast address."},

0xC00D0039: { "code": "NS_E_BAD_ADAPTER_ADDRESS", "message":"The specified adapter address is invalid."},

0xC00D003A: { "code": "NS_E_BAD_DELIVERY_MODE", "message":"The specified delivery mode is invalid."},

0xC00D003B: { "code": "NS_E_INVALID_CHANNEL", "message":"The specified station does not exist."},

0xC00D003C: { "code": "NS_E_INVALID_STREAM", "message":"The specified stream does not exist."},

0xC00D003D: { "code": "NS_E_INVALID_ARCHIVE", "message":"The specified archive could not be opened."},

0xC00D003E: { "code": "NS_E_NOTITLES", "message":"The system cannot find any titles on the server."},

0xC00D003F: { "code": "NS_E_INVALID_CLIENT", "message":"The system cannot find the client specified."},

0xC00D0040: { "code": "NS_E_INVALID_BLACKHOLE_ADDRESS", "message":"The Blackhole Address is not initialized."},

0xC00D0041: { "code": "NS_E_INCOMPATIBLE_FORMAT", "message":"The station does not support the stream format."},

0xC00D0042: { "code": "NS_E_INVALID_KEY", "message":"The specified key is not valid."},

0xC00D0043: { "code": "NS_E_INVALID_PORT", "message":"The specified port is not valid."},

0xC00D0044: { "code": "NS_E_INVALID_TTL", "message":"The specified TTL is not valid."},

0xC00D0045: { "code": "NS_E_STRIDE_REFUSED", "message":"The request to fast forward or rewind could not be fulfilled."},

0xC00D0046: { "code": "NS_E_MMSAUTOSERVER_CANTFINDWALKER", "message":"Unable to load the appropriate file parser."},

0xC00D0047: { "code": "NS_E_MAX_BITRATE", "message":"Cannot exceed the maximum bandwidth limit."},

0xC00D0048: { "code": "NS_E_LOGFILEPERIOD", "message":"Invalid value for LogFilePeriod."},

0xC00D0049: { "code": "NS_E_MAX_CLIENTS", "message":"Cannot exceed the maximum client limit."},

0xC00D004A: { "code": "NS_E_LOG_FILE_SIZE", "message":"The maximum log file size has been reached."},

0xC00D004B: { "code": "NS_E_MAX_FILERATE", "message":"Cannot exceed the maximum file rate."},

0xC00D004C: { "code": "NS_E_WALKER_UNKNOWN", "message":"Unknown file type."},

0xC00D004D: { "code": "NS_E_WALKER_SERVER", "message":"The specified file, %1, cannot be loaded onto the specified server, %2."},

0xC00D004E: { "code": "NS_E_WALKER_USAGE", "message":"There was a usage error with file parser."},

0xC00D0050: { "code": "NS_E_TIGER_FAIL", "message":"The Title Server %1 has failed."},

0xC00D0053: { "code": "NS_E_CUB_FAIL", "message":"Content Server %1 (%2) has failed."},

0xC00D0055: { "code": "NS_E_DISK_FAIL", "message":"Disk %1 ( %2 ) on Content Server %3, has failed."},

0xC00D0060: { "code": "NS_E_MAX_FUNNELS_ALERT", "message":"The NetShow data stream limit of %1 streams was reached."},

0xC00D0061: { "code": "NS_E_ALLOCATE_FILE_FAIL", "message":"The NetShow Video Server was unable to allocate a %1 block file named %2."},

0xC00D0062: { "code": "NS_E_PAGING_ERROR", "message":"A Content Server was unable to page a block."},

0xC00D0063: { "code": "NS_E_BAD_BLOCK0_VERSION", "message":"Disk %1 has unrecognized control block version %2."},

0xC00D0064: { "code": "NS_E_BAD_DISK_UID", "message":"Disk %1 has incorrect uid %2."},

0xC00D0065: { "code": "NS_E_BAD_FSMAJOR_VERSION", "message":"Disk %1 has unsupported file system major version %2."},

0xC00D0066: { "code": "NS_E_BAD_STAMPNUMBER", "message":"Disk %1 has bad stamp number in control block."},

0xC00D0067: { "code": "NS_E_PARTIALLY_REBUILT_DISK", "message":"Disk %1 is partially reconstructed."},

0xC00D0068: { "code": "NS_E_ENACTPLAN_GIVEUP", "message":"EnactPlan gives up."},

0xC00D006A: { "code": "MCMADM_E_REGKEY_NOT_FOUND", "message":"The key was not found in the registry."},

0xC00D006B: { "code": "NS_E_NO_FORMATS", "message":"The publishing point cannot be started because the server does not have the appropriate stream formats. Use the Multicast Announcement Wizard to create a new announcement for this publishing point."},

0xC00D006C: { "code": "NS_E_NO_REFERENCES", "message":"No reference URLs were found in an ASX file."},

0xC00D006D: { "code": "NS_E_WAVE_OPEN", "message":"Error opening wave device, the device might be in use."},

0xC00D006F: { "code": "NS_E_CANNOTCONNECTEVENTS", "message":"Unable to establish a connection to the NetShow event monitor service."},

0xC00D0071: { "code": "NS_E_NO_DEVICE", "message":"No device driver is present on the system."},

0xC00D0072: { "code": "NS_E_NO_SPECIFIED_DEVICE", "message":"No specified device driver is present."},

0xC00D00C8: { "code": "NS_E_MONITOR_GIVEUP", "message":"Netshow Events Monitor is not operational and has been disconnected."},

0xC00D00C9: { "code": "NS_E_REMIRRORED_DISK", "message":"Disk %1 is remirrored."},

0xC00D00CA: { "code": "NS_E_INSUFFICIENT_DATA", "message":"Insufficient data found."},

0xC00D00CB: { "code": "NS_E_ASSERT", "message":"1 failed in file %2 line %3."},

0xC00D00CC: { "code": "NS_E_BAD_ADAPTER_NAME", "message":"The specified adapter name is invalid."},

0xC00D00CD: { "code": "NS_E_NOT_LICENSED", "message":"The application is not licensed for this feature."},

0xC00D00CE: { "code": "NS_E_NO_SERVER_CONTACT", "message":"Unable to contact the server."},

0xC00D00CF: { "code": "NS_E_TOO_MANY_TITLES", "message":"Maximum number of titles exceeded."},

0xC00D00D0: { "code": "NS_E_TITLE_SIZE_EXCEEDED", "message":"Maximum size of a title exceeded."},

0xC00D00D1: { "code": "NS_E_UDP_DISABLED", "message":"UDP protocol not enabled. Not trying %1!ls!."},

0xC00D00D2: { "code": "NS_E_TCP_DISABLED", "message":"TCP protocol not enabled. Not trying %1!ls!."},

0xC00D00D3: { "code": "NS_E_HTTP_DISABLED", "message":"HTTP protocol not enabled. Not trying %1!ls!."},

0xC00D00D4: { "code": "NS_E_LICENSE_EXPIRED", "message":"The product license has expired."},

0xC00D00D5: { "code": "NS_E_TITLE_BITRATE", "message":"Source file exceeds the per title maximum bitrate. See NetShow Theater documentation for more information."},

0xC00D00D6: { "code": "NS_E_EMPTY_PROGRAM_NAME", "message":"The program name cannot be empty."},

0xC00D00D7: { "code": "NS_E_MISSING_CHANNEL", "message":"Station %1 does not exist."},

0xC00D00D8: { "code": "NS_E_NO_CHANNELS", "message":"You need to define at least one station before this operation can complete."},

0xC00D00D9: { "code": "NS_E_INVALID_INDEX2", "message":"The index specified is invalid."},

0xC00D0190: { "code": "NS_E_CUB_FAIL_LINK", "message":"Content Server %1 (%2) has failed its link to Content Server %3."},

0xC00D0192: { "code": "NS_E_BAD_CUB_UID", "message":"Content Server %1 (%2) has incorrect uid %3."},

0xC00D0195: { "code": "NS_E_GLITCH_MODE", "message":"Server unreliable because multiple components failed."},

0xC00D019B: { "code": "NS_E_NO_MEDIA_PROTOCOL", "message":"Content Server %1 (%2) is unable to communicate with the Media System Network Protocol."},

0xC00D07F1: { "code": "NS_E_NOTHING_TO_DO", "message":"Nothing to do."},

0xC00D07F2: { "code": "NS_E_NO_MULTICAST", "message":"Not receiving data from the server."},

0xC00D0BB8: { "code": "NS_E_INVALID_INPUT_FORMAT", "message":"The input media format is invalid."},

0xC00D0BB9: { "code": "NS_E_MSAUDIO_NOT_INSTALLED", "message":"The MSAudio codec is not installed on this system."},

0xC00D0BBA: { "code": "NS_E_UNEXPECTED_MSAUDIO_ERROR", "message":"An unexpected error occurred with the MSAudio codec."},

0xC00D0BBB: { "code": "NS_E_INVALID_OUTPUT_FORMAT", "message":"The output media format is invalid."},

0xC00D0BBC: { "code": "NS_E_NOT_CONFIGURED", "message":"The object must be fully configured before audio samples can be processed."},

0xC00D0BBD: { "code": "NS_E_PROTECTED_CONTENT", "message":"You need a license to perform the requested operation on this media file."},

0xC00D0BBE: { "code": "NS_E_LICENSE_REQUIRED", "message":"You need a license to perform the requested operation on this media file."},

0xC00D0BBF: { "code": "NS_E_TAMPERED_CONTENT", "message":"This media file is corrupted or invalid. Contact the content provider for a new file."},

0xC00D0BC0: { "code": "NS_E_LICENSE_OUTOFDATE", "message":"The license for this media file has expired. Get a new license or contact the content provider for further assistance."},

0xC00D0BC1: { "code": "NS_E_LICENSE_INCORRECT_RIGHTS", "message":"You are not allowed to open this file. Contact the content provider for further assistance."},

0xC00D0BC2: { "code": "NS_E_AUDIO_CODEC_NOT_INSTALLED", "message":"The requested audio codec is not installed on this system."},

0xC00D0BC3: { "code": "NS_E_AUDIO_CODEC_ERROR", "message":"An unexpected error occurred with the audio codec."},

0xC00D0BC4: { "code": "NS_E_VIDEO_CODEC_NOT_INSTALLED", "message":"The requested video codec is not installed on this system."},

0xC00D0BC5: { "code": "NS_E_VIDEO_CODEC_ERROR", "message":"An unexpected error occurred with the video codec."},

0xC00D0BC6: { "code": "NS_E_INVALIDPROFILE", "message":"The Profile is invalid."},

0xC00D0BC7: { "code": "NS_E_INCOMPATIBLE_VERSION", "message":"A new version of the SDK is needed to play the requested content."},

0xC00D0BCA: { "code": "NS_E_OFFLINE_MODE", "message":"The requested URL is not available in offline mode."},

0xC00D0BCB: { "code": "NS_E_NOT_CONNECTED", "message":"The requested URL cannot be accessed because there is no network connection."},

0xC00D0BCC: { "code": "NS_E_TOO_MUCH_DATA", "message":"The encoding process was unable to keep up with the amount of supplied data."},

0xC00D0BCD: { "code": "NS_E_UNSUPPORTED_PROPERTY", "message":"The given property is not supported."},

0xC00D0BCE: { "code": "NS_E_8BIT_WAVE_UNSUPPORTED", "message":"Windows Media Player cannot copy the files to the CD because they are 8-bit. Convert the files to 16-bit, 44-kHz stereo files by using Sound Recorder or another audio-processing program, and then try again."},

0xC00D0BCF: { "code": "NS_E_NO_MORE_SAMPLES", "message":"There are no more samples in the current range."},

0xC00D0BD0: { "code": "NS_E_INVALID_SAMPLING_RATE", "message":"The given sampling rate is invalid."},

0xC00D0BD1: { "code": "NS_E_MAX_PACKET_SIZE_TOO_SMALL", "message":"The given maximum packet size is too small to accommodate this profile.)"},

0xC00D0BD2: { "code": "NS_E_LATE_PACKET", "message":"The packet arrived too late to be of use."},

0xC00D0BD3: { "code": "NS_E_DUPLICATE_PACKET", "message":"The packet is a duplicate of one received before."},

0xC00D0BD4: { "code": "NS_E_SDK_BUFFERTOOSMALL", "message":"Supplied buffer is too small."},

0xC00D0BD5: { "code": "NS_E_INVALID_NUM_PASSES", "message":"The wrong number of preprocessing passes was used for the stream's output type."},

0xC00D0BD6: { "code": "NS_E_ATTRIBUTE_READ_ONLY", "message":"An attempt was made to add, modify, or delete a read only attribute."},

0xC00D0BD7: { "code": "NS_E_ATTRIBUTE_NOT_ALLOWED", "message":"An attempt was made to add attribute that is not allowed for the given media type."},

0xC00D0BD8: { "code": "NS_E_INVALID_EDL", "message":"The EDL provided is invalid."},

0xC00D0BD9: { "code": "NS_E_DATA_UNIT_EXTENSION_TOO_LARGE", "message":"The Data Unit Extension data was too large to be used."},

0xC00D0BDA: { "code": "NS_E_CODEC_DMO_ERROR", "message":"An unexpected error occurred with a DMO codec."},

0xC00D0BDC: { "code": "NS_E_FEATURE_DISABLED_BY_GROUP_POLICY", "message":"This feature has been disabled by group policy."},

0xC00D0BDD: { "code": "NS_E_FEATURE_DISABLED_IN_SKU", "message":"This feature is disabled in this SKU."},

0xC00D0FA0: { "code": "NS_E_NO_CD", "message":"There is no CD in the CD drive. Insert a CD, and then try again."},

0xC00D0FA1: { "code": "NS_E_CANT_READ_DIGITAL", "message":"Windows Media Player could not use digital playback to play the CD. To switch to analog playback, on the Tools menu, click Options, and then click the Devices tab. Double-click the CD drive, and then in the Playback area, click Analog. For additional assistance, click Web Help."},

0xC00D0FA2: { "code": "NS_E_DEVICE_DISCONNECTED", "message":"Windows Media Player no longer detects a connected portable device. Reconnect your portable device, and then try synchronizing the file again."},

0xC00D0FA3: { "code": "NS_E_DEVICE_NOT_SUPPORT_FORMAT", "message":"Windows Media Player cannot play the file. The portable device does not support the specified file type."},

0xC00D0FA4: { "code": "NS_E_SLOW_READ_DIGITAL", "message":"Windows Media Player could not use digital playback to play the CD. The Player has automatically switched the CD drive to analog playback. To switch back to digital CD playback, use the Devices tab. For additional assistance, click Web Help."},

0xC00D0FA5: { "code": "NS_E_MIXER_INVALID_LINE", "message":"An invalid line error occurred in the mixer."},

0xC00D0FA6: { "code": "NS_E_MIXER_INVALID_CONTROL", "message":"An invalid control error occurred in the mixer."},

0xC00D0FA7: { "code": "NS_E_MIXER_INVALID_VALUE", "message":"An invalid value error occurred in the mixer."},

0xC00D0FA8: { "code": "NS_E_MIXER_UNKNOWN_MMRESULT", "message":"An unrecognized MMRESULT occurred in the mixer."},

0xC00D0FA9: { "code": "NS_E_USER_STOP", "message":"User has stopped the operation."},

0xC00D0FAA: { "code": "NS_E_MP3_FORMAT_NOT_FOUND", "message":"Windows Media Player cannot rip the track because a compatible MP3 encoder is not installed on your computer. Install a compatible MP3 encoder or choose a different format to rip to (such as Windows Media Audio)."},

0xC00D0FAB: { "code": "NS_E_CD_READ_ERROR_NO_CORRECTION", "message":"Windows Media Player cannot read the CD. The disc might be dirty or damaged. Turn on error correction, and then try again."},

0xC00D0FAC: { "code": "NS_E_CD_READ_ERROR", "message":"Windows Media Player cannot read the CD. The disc might be dirty or damaged or the CD drive might be malfunctioning."},

0xC00D0FAD: { "code": "NS_E_CD_SLOW_COPY", "message":"For best performance, do not play CD tracks while ripping them."},

0xC00D0FAE: { "code": "NS_E_CD_COPYTO_CD", "message":"It is not possible to directly burn tracks from one CD to another CD. You must first rip the tracks from the CD to your computer, and then burn the files to a blank CD."},

0xC00D0FAF: { "code": "NS_E_MIXER_NODRIVER", "message":"Could not open a sound mixer driver."},

0xC00D0FB0: { "code": "NS_E_REDBOOK_ENABLED_WHILE_COPYING", "message":"Windows Media Player cannot rip tracks from the CD correctly because the CD drive settings in Device Manager do not match the CD drive settings in the Player."},

0xC00D0FB1: { "code": "NS_E_CD_REFRESH", "message":"Windows Media Player is busy reading the CD."},

0xC00D0FB2: { "code": "NS_E_CD_DRIVER_PROBLEM", "message":"Windows Media Player could not use digital playback to play the CD. The Player has automatically switched the CD drive to analog playback. To switch back to digital CD playback, use the Devices tab. For additional assistance, click Web Help."},

0xC00D0FB3: { "code": "NS_E_WONT_DO_DIGITAL", "message":"Windows Media Player could not use digital playback to play the CD. The Player has automatically switched the CD drive to analog playback. To switch back to digital CD playback, use the Devices tab. For additional assistance, click Web Help."},

0xC00D0FB4: { "code": "NS_E_WMPXML_NOERROR", "message":"A call was made to GetParseError on the XML parser but there was no error to retrieve."},

0xC00D0FB5: { "code": "NS_E_WMPXML_ENDOFDATA", "message":"The XML Parser ran out of data while parsing."},

0xC00D0FB6: { "code": "NS_E_WMPXML_PARSEERROR", "message":"A generic parse error occurred in the XML parser but no information is available."},

0xC00D0FB7: { "code": "NS_E_WMPXML_ATTRIBUTENOTFOUND", "message":"A call get GetNamedAttribute or GetNamedAttributeIndex on the XML parser resulted in the index not being found."},

0xC00D0FB8: { "code": "NS_E_WMPXML_PINOTFOUND", "message":"A call was made go GetNamedPI on the XML parser, but the requested Processing Instruction was not found."},

0xC00D0FB9: { "code": "NS_E_WMPXML_EMPTYDOC", "message":"Persist was called on the XML parser, but the parser has no data to persist."},

0xC00D0FBA: { "code": "NS_E_WMP_PATH_ALREADY_IN_LIBRARY", "message":"This file path is already in the library."},

0xC00D0FBE: { "code": "NS_E_WMP_FILESCANALREADYSTARTED", "message":"Windows Media Player is already searching for files to add to your library. Wait for the current process to finish before attempting to search again."},

0xC00D0FBF: { "code": "NS_E_WMP_HME_INVALIDOBJECTID", "message":"Windows Media Player is unable to find the media you are looking for."},

0xC00D0FC0: { "code": "NS_E_WMP_MF_CODE_EXPIRED", "message":"A component of Windows Media Player is out-of-date. If you are running a pre-release version of Windows, try upgrading to a more recent version."},

0xC00D0FC1: { "code": "NS_E_WMP_HME_NOTSEARCHABLEFORITEMS", "message":"This container does not support search on items."},

0xC00D0FC7: { "code": "NS_E_WMP_ADDTOLIBRARY_FAILED", "message":"Windows Media Player encountered a problem while adding one or more files to the library. For additional assistance, click Web Help."},

0xC00D0FC8: { "code": "NS_E_WMP_WINDOWSAPIFAILURE", "message":"A Windows API call failed but no error information was available."},

0xC00D0FC9: { "code": "NS_E_WMP_RECORDING_NOT_ALLOWED", "message":"This file does not have burn rights. If you obtained this file from an online store, go to the online store to get burn rights."},

0xC00D0FCA: { "code": "NS_E_DEVICE_NOT_READY", "message":"Windows Media Player no longer detects a connected portable device. Reconnect your portable device, and then try to sync the file again."},

0xC00D0FCB: { "code": "NS_E_DAMAGED_FILE", "message":"Windows Media Player cannot play the file because it is corrupted."},

0xC00D0FCC: { "code": "NS_E_MPDB_GENERIC", "message":"Windows Media Player encountered an error while attempting to access information in the library. Try restarting the Player."},

0xC00D0FCD: { "code": "NS_E_FILE_FAILED_CHECKS", "message":"The file cannot be added to the library because it is smaller than the \"Skip files smaller than\" setting. To add the file, change the setting on the Library tab. For additional assistance, click Web Help."},

0xC00D0FCE: { "code": "NS_E_MEDIA_LIBRARY_FAILED", "message":"Windows Media Player cannot create the library. You must be logged on as an administrator or a member of the Administrators group to install the Player. For more information, contact your system administrator."},

0xC00D0FCF: { "code": "NS_E_SHARING_VIOLATION", "message":"The file is already in use. Close other programs that might be using the file, or stop playing the file, and then try again."},

0xC00D0FD0: { "code": "NS_E_NO_ERROR_STRING_FOUND", "message":"Windows Media Player has encountered an unknown error."},

0xC00D0FD1: { "code": "NS_E_WMPOCX_NO_REMOTE_CORE", "message":"The Windows Media Player ActiveX control cannot connect to remote media services, but will continue with local media services."},

0xC00D0FD2: { "code": "NS_E_WMPOCX_NO_ACTIVE_CORE", "message":"The requested method or property is not available because the Windows Media Player ActiveX control has not been properly activated."},

0xC00D0FD3: { "code": "NS_E_WMPOCX_NOT_RUNNING_REMOTELY", "message":"The Windows Media Player ActiveX control is not running in remote mode."},

0xC00D0FD4: { "code": "NS_E_WMPOCX_NO_REMOTE_WINDOW", "message":"An error occurred while trying to get the remote Windows Media Player window."},

0xC00D0FD5: { "code": "NS_E_WMPOCX_ERRORMANAGERNOTAVAILABLE", "message":"Windows Media Player has encountered an unknown error."},

0xC00D0FD6: { "code": "NS_E_PLUGIN_NOTSHUTDOWN", "message":"Windows Media Player was not closed properly. A damaged or incompatible plug-in might have caused the problem to occur. As a precaution, all optional plug-ins have been disabled."},

0xC00D0FD7: { "code": "NS_E_WMP_CANNOT_FIND_FOLDER", "message":"Windows Media Player cannot find the specified path. Verify that the path is typed correctly. If it is, the path does not exist in the specified location, or the computer where the path is located is not available."},

0xC00D0FD8: { "code": "NS_E_WMP_STREAMING_RECORDING_NOT_ALLOWED", "message":"Windows Media Player cannot save a file that is being streamed."},

0xC00D0FD9: { "code": "NS_E_WMP_PLUGINDLL_NOTFOUND", "message":"Windows Media Player cannot find the selected plug-in. The Player will try to remove it from the menu. To use this plug-in, install it again."},

0xC00D0FDA: { "code": "NS_E_NEED_TO_ASK_USER", "message":"Action requires input from the user."},

0xC00D0FDB: { "code": "NS_E_WMPOCX_PLAYER_NOT_DOCKED", "message":"The Windows Media Player ActiveX control must be in a docked state for this action to be performed."},

0xC00D0FDC: { "code": "NS_E_WMP_EXTERNAL_NOTREADY", "message":"The Windows Media Player external object is not ready."},

0xC00D0FDD: { "code": "NS_E_WMP_MLS_STALE_DATA", "message":"Windows Media Player cannot perform the requested action. Your computer's time and date might not be set correctly."},

0xC00D0FDE: { "code": "NS_E_WMP_UI_SUBCONTROLSNOTSUPPORTED", "message":"The control (%s) does not support creation of sub-controls, yet (%d) sub-controls have been specified."},

0xC00D0FDF: { "code": "NS_E_WMP_UI_VERSIONMISMATCH", "message":"Version mismatch: (%.1f required, %.1f found)."},

0xC00D0FE0: { "code": "NS_E_WMP_UI_NOTATHEMEFILE", "message":"The layout manager was given valid XML that wasn't a theme file."},

0xC00D0FE1: { "code": "NS_E_WMP_UI_SUBELEMENTNOTFOUND", "message":"The %s subelement could not be found on the %s object."},

0xC00D0FE2: { "code": "NS_E_WMP_UI_VERSIONPARSE", "message":"An error occurred parsing the version tag. Valid version tags are of the form: <?wmp version='1.0'?>."},

0xC00D0FE3: { "code": "NS_E_WMP_UI_VIEWIDNOTFOUND", "message":"The view specified in for the 'currentViewID' property (%s) was not found in this theme file."},

0xC00D0FE4: { "code": "NS_E_WMP_UI_PASSTHROUGH", "message":"This error used internally for hit testing."},

0xC00D0FE5: { "code": "NS_E_WMP_UI_OBJECTNOTFOUND", "message":"Attributes were specified for the %s object, but the object was not available to send them to."},

0xC00D0FE6: { "code": "NS_E_WMP_UI_SECONDHANDLER", "message":"The %s event already has a handler, the second handler was ignored."},

0xC00D0FE7: { "code": "NS_E_WMP_UI_NOSKININZIP", "message":"No .wms file found in skin archive."},

0xC00D0FEA: { "code": "NS_E_WMP_URLDOWNLOADFAILED", "message":"Windows Media Player encountered a problem while downloading the file. For additional assistance, click Web Help."},

0xC00D0FEB: { "code": "NS_E_WMPOCX_UNABLE_TO_LOAD_SKIN", "message":"The Windows Media Player ActiveX control cannot load the requested uiMode and cannot roll back to the existing uiMode."},

0xC00D0FEC: { "code": "NS_E_WMP_INVALID_SKIN", "message":"Windows Media Player encountered a problem with the skin file. The skin file might not be valid."},

0xC00D0FED: { "code": "NS_E_WMP_SENDMAILFAILED", "message":"Windows Media Player cannot send the link because your email program is not responding. Verify that your email program is configured properly, and then try again. For more information about email, see Windows Help."},

0xC00D0FEE: { "code": "NS_E_WMP_LOCKEDINSKINMODE", "message":"Windows Media Player cannot switch to full mode because your computer administrator has locked this skin."},

0xC00D0FEF: { "code": "NS_E_WMP_FAILED_TO_SAVE_FILE", "message":"Windows Media Player encountered a problem while saving the file. For additional assistance, click Web Help."},

0xC00D0FF0: { "code": "NS_E_WMP_SAVEAS_READONLY", "message":"Windows Media Player cannot overwrite a read-only file. Try using a different file name."},

0xC00D0FF1: { "code": "NS_E_WMP_FAILED_TO_SAVE_PLAYLIST", "message":"Windows Media Player encountered a problem while creating or saving the playlist. For additional assistance, click Web Help."},

0xC00D0FF2: { "code": "NS_E_WMP_FAILED_TO_OPEN_WMD", "message":"Windows Media Player cannot open the Windows Media Download file. The file might be damaged."},

0xC00D0FF3: { "code": "NS_E_WMP_CANT_PLAY_PROTECTED", "message":"The file cannot be added to the library because it is a protected DVR-MS file. This content cannot be played back by Windows Media Player."},

0xC00D0FF4: { "code": "NS_E_SHARING_STATE_OUT_OF_SYNC", "message":"Media sharing has been turned off because a required Windows setting or component has changed. For additional assistance, click Web Help."},

0xC00D0FFA: { "code": "NS_E_WMPOCX_REMOTE_PLAYER_ALREADY_RUNNING", "message":"Exclusive Services launch failed because the Windows Media Player is already running."},

0xC00D1004: { "code": "NS_E_WMP_RBC_JPGMAPPINGIMAGE", "message":"JPG Images are not recommended for use as a mappingImage."},

0xC00D1005: { "code": "NS_E_WMP_JPGTRANSPARENCY", "message":"JPG Images are not recommended when using a transparencyColor."},

0xC00D1009: { "code": "NS_E_WMP_INVALID_MAX_VAL", "message":"The Max property cannot be less than Min property."},

0xC00D100A: { "code": "NS_E_WMP_INVALID_MIN_VAL", "message":"The Min property cannot be greater than Max property."},

0xC00D100E: { "code": "NS_E_WMP_CS_JPGPOSITIONIMAGE", "message":"JPG Images are not recommended for use as a positionImage."},

0xC00D100F: { "code": "NS_E_WMP_CS_NOTEVENLYDIVISIBLE", "message":"The (%s) image's size is not evenly divisible by the positionImage's size."},

0xC00D1018: { "code": "NS_E_WMPZIP_NOTAZIPFILE", "message":"The ZIP reader opened a file and its signature did not match that of the ZIP files."},

0xC00D1019: { "code": "NS_E_WMPZIP_CORRUPT", "message":"The ZIP reader has detected that the file is corrupted."},

0xC00D101A: { "code": "NS_E_WMPZIP_FILENOTFOUND", "message":"GetFileStream, SaveToFile, or SaveTemp file was called on the ZIP reader with a file name that was not found in the ZIP file."},

0xC00D1022: { "code": "NS_E_WMP_IMAGE_FILETYPE_UNSUPPORTED", "message":"Image type not supported."},

0xC00D1023: { "code": "NS_E_WMP_IMAGE_INVALID_FORMAT", "message":"Image file might be corrupt."},

0xC00D1024: { "code": "NS_E_WMP_GIF_UNEXPECTED_ENDOFFILE", "message":"Unexpected end of file. GIF file might be corrupt."},

0xC00D1025: { "code": "NS_E_WMP_GIF_INVALID_FORMAT", "message":"Invalid GIF file."},

0xC00D1026: { "code": "NS_E_WMP_GIF_BAD_VERSION_NUMBER", "message":"Invalid GIF version. Only 87a or 89a supported."},

0xC00D1027: { "code": "NS_E_WMP_GIF_NO_IMAGE_IN_FILE", "message":"No images found in GIF file."},

0xC00D1028: { "code": "NS_E_WMP_PNG_INVALIDFORMAT", "message":"Invalid PNG image file format."},

0xC00D1029: { "code": "NS_E_WMP_PNG_UNSUPPORTED_BITDEPTH", "message":"PNG bitdepth not supported."},

0xC00D102A: { "code": "NS_E_WMP_PNG_UNSUPPORTED_COMPRESSION", "message":"Compression format defined in PNG file not supported,"},

0xC00D102B: { "code": "NS_E_WMP_PNG_UNSUPPORTED_FILTER", "message":"Filter method defined in PNG file not supported."},

0xC00D102C: { "code": "NS_E_WMP_PNG_UNSUPPORTED_INTERLACE", "message":"Interlace method defined in PNG file not supported."},

0xC00D102D: { "code": "NS_E_WMP_PNG_UNSUPPORTED_BAD_CRC", "message":"Bad CRC in PNG file."},

0xC00D102E: { "code": "NS_E_WMP_BMP_INVALID_BITMASK", "message":"Invalid bitmask in BMP file."},

0xC00D102F: { "code": "NS_E_WMP_BMP_TOPDOWN_DIB_UNSUPPORTED", "message":"Topdown DIB not supported."},

0xC00D1030: { "code": "NS_E_WMP_BMP_BITMAP_NOT_CREATED", "message":"Bitmap could not be created."},

0xC00D1031: { "code": "NS_E_WMP_BMP_COMPRESSION_UNSUPPORTED", "message":"Compression format defined in BMP not supported."},

0xC00D1032: { "code": "NS_E_WMP_BMP_INVALID_FORMAT", "message":"Invalid Bitmap format."},

0xC00D1033: { "code": "NS_E_WMP_JPG_JERR_ARITHCODING_NOTIMPL", "message":"JPEG Arithmetic coding not supported."},

0xC00D1034: { "code": "NS_E_WMP_JPG_INVALID_FORMAT", "message":"Invalid JPEG format."},

0xC00D1035: { "code": "NS_E_WMP_JPG_BAD_DCTSIZE", "message":"Invalid JPEG format."},

0xC00D1036: { "code": "NS_E_WMP_JPG_BAD_VERSION_NUMBER", "message":"Internal version error. Unexpected JPEG library version."},

0xC00D1037: { "code": "NS_E_WMP_JPG_BAD_PRECISION", "message":"Internal JPEG Library error. Unsupported JPEG data precision."},

0xC00D1038: { "code": "NS_E_WMP_JPG_CCIR601_NOTIMPL", "message":"JPEG CCIR601 not supported."},

0xC00D1039: { "code": "NS_E_WMP_JPG_NO_IMAGE_IN_FILE", "message":"No image found in JPEG file."},

0xC00D103A: { "code": "NS_E_WMP_JPG_READ_ERROR", "message":"Could not read JPEG file."},

0xC00D103B: { "code": "NS_E_WMP_JPG_FRACT_SAMPLE_NOTIMPL", "message":"JPEG Fractional sampling not supported."},

0xC00D103C: { "code": "NS_E_WMP_JPG_IMAGE_TOO_BIG", "message":"JPEG image too large. Maximum image size supported is 65500 X 65500."},

0xC00D103D: { "code": "NS_E_WMP_JPG_UNEXPECTED_ENDOFFILE", "message":"Unexpected end of file reached in JPEG file."},

0xC00D103E: { "code": "NS_E_WMP_JPG_SOF_UNSUPPORTED", "message":"Unsupported JPEG SOF marker found."},

0xC00D103F: { "code": "NS_E_WMP_JPG_UNKNOWN_MARKER", "message":"Unknown JPEG marker found."},

0xC00D1044: { "code": "NS_E_WMP_FAILED_TO_OPEN_IMAGE", "message":"Windows Media Player cannot display the picture file. The player either does not support the picture type or the picture is corrupted."},

0xC00D1049: { "code": "NS_E_WMP_DAI_SONGTOOSHORT", "message":"Windows Media Player cannot compute a Digital Audio Id for the song. It is too short."},

0xC00D104A: { "code": "NS_E_WMG_RATEUNAVAILABLE", "message":"Windows Media Player cannot play the file at the requested speed."},

0xC00D104B: { "code": "NS_E_WMG_PLUGINUNAVAILABLE", "message":"The rendering or digital signal processing plug-in cannot be instantiated."},

0xC00D104C: { "code": "NS_E_WMG_CANNOTQUEUE", "message":"The file cannot be queued for seamless playback."},

0xC00D104D: { "code": "NS_E_WMG_PREROLLLICENSEACQUISITIONNOTALLOWED", "message":"Windows Media Player cannot download media usage rights for a file in the playlist."},

0xC00D104E: { "code": "NS_E_WMG_UNEXPECTEDPREROLLSTATUS", "message":"Windows Media Player encountered an error while trying to queue a file."},

0xC00D1051: { "code": "NS_E_WMG_INVALID_COPP_CERTIFICATE", "message":"Windows Media Player cannot play the protected file. The Player cannot verify that the connection to your video card is secure. Try installing an updated device driver for your video card."},

0xC00D1052: { "code": "NS_E_WMG_COPP_SECURITY_INVALID", "message":"Windows Media Player cannot play the protected file. The Player detected that the connection to your hardware might not be secure."},

0xC00D1053: { "code": "NS_E_WMG_COPP_UNSUPPORTED", "message":"Windows Media Player output link protection is unsupported on this system."},

0xC00D1054: { "code": "NS_E_WMG_INVALIDSTATE", "message":"Operation attempted in an invalid graph state."},

0xC00D1055: { "code": "NS_E_WMG_SINKALREADYEXISTS", "message":"A renderer cannot be inserted in a stream while one already exists."},

0xC00D1056: { "code": "NS_E_WMG_NOSDKINTERFACE", "message":"The Windows Media SDK interface needed to complete the operation does not exist at this time."},

0xC00D1057: { "code": "NS_E_WMG_NOTALLOUTPUTSRENDERED", "message":"Windows Media Player cannot play a portion of the file because it requires a codec that either could not be downloaded or that is not supported by the Player."},

0xC00D1058: { "code": "NS_E_WMG_FILETRANSFERNOTALLOWED", "message":"File transfer streams are not allowed in the standalone Player."},

0xC00D1059: { "code": "NS_E_WMR_UNSUPPORTEDSTREAM", "message":"Windows Media Player cannot play the file. The Player does not support the format you are trying to play."},

0xC00D105A: { "code": "NS_E_WMR_PINNOTFOUND", "message":"An operation was attempted on a pin that does not exist in the DirectShow filter graph."},

0xC00D105B: { "code": "NS_E_WMR_WAITINGONFORMATSWITCH", "message":"Specified operation cannot be completed while waiting for a media format change from the SDK."},

0xC00D105C: { "code": "NS_E_WMR_NOSOURCEFILTER", "message":"Specified operation cannot be completed because the source filter does not exist."},

0xC00D105D: { "code": "NS_E_WMR_PINTYPENOMATCH", "message":"The specified type does not match this pin."},

0xC00D105E: { "code": "NS_E_WMR_NOCALLBACKAVAILABLE", "message":"The WMR Source Filter does not have a callback available."},

0xC00D1062: { "code": "NS_E_WMR_SAMPLEPROPERTYNOTSET", "message":"The specified property has not been set on this sample."},

0xC00D1063: { "code": "NS_E_WMR_CANNOT_RENDER_BINARY_STREAM", "message":"A plug-in is required to correctly play the file. To determine if the plug-in is available to download, click Web Help."},

0xC00D1064: { "code": "NS_E_WMG_LICENSE_TAMPERED", "message":"Windows Media Player cannot play the file because your media usage rights are corrupted. If you previously backed up your media usage rights, try restoring them."},

0xC00D1065: { "code": "NS_E_WMR_WILLNOT_RENDER_BINARY_STREAM", "message":"Windows Media Player cannot play protected files that contain binary streams."},

0xC00D1068: { "code": "NS_E_WMX_UNRECOGNIZED_PLAYLIST_FORMAT", "message":"Windows Media Player cannot play the playlist because it is not valid."},

0xC00D1069: { "code": "NS_E_ASX_INVALIDFORMAT", "message":"Windows Media Player cannot play the playlist because it is not valid."},

0xC00D106A: { "code": "NS_E_ASX_INVALIDVERSION", "message":"A later version of Windows Media Player might be required to play this playlist."},

0xC00D106B: { "code": "NS_E_ASX_INVALID_REPEAT_BLOCK", "message":"The format of a REPEAT loop within the current playlist file is not valid."},

0xC00D106C: { "code": "NS_E_ASX_NOTHING_TO_WRITE", "message":"Windows Media Player cannot save the playlist because it does not contain any items."},

0xC00D106D: { "code": "NS_E_URLLIST_INVALIDFORMAT", "message":"Windows Media Player cannot play the playlist because it is not valid."},

0xC00D106E: { "code": "NS_E_WMX_ATTRIBUTE_DOES_NOT_EXIST", "message":"The specified attribute does not exist."},

0xC00D106F: { "code": "NS_E_WMX_ATTRIBUTE_ALREADY_EXISTS", "message":"The specified attribute already exists."},

0xC00D1070: { "code": "NS_E_WMX_ATTRIBUTE_UNRETRIEVABLE", "message":"Cannot retrieve the specified attribute."},

0xC00D1071: { "code": "NS_E_WMX_ITEM_DOES_NOT_EXIST", "message":"The specified item does not exist in the current playlist."},

0xC00D1072: { "code": "NS_E_WMX_ITEM_TYPE_ILLEGAL", "message":"Items of the specified type cannot be created within the current playlist."},

0xC00D1073: { "code": "NS_E_WMX_ITEM_UNSETTABLE", "message":"The specified item cannot be set in the current playlist."},

0xC00D1074: { "code": "NS_E_WMX_PLAYLIST_EMPTY", "message":"Windows Media Player cannot perform the requested action because the playlist does not contain any items."},

0xC00D1075: { "code": "NS_E_MLS_SMARTPLAYLIST_FILTER_NOT_REGISTERED", "message":"The specified auto playlist contains a filter type that is either not valid or is not installed on this computer."},

0xC00D1076: { "code": "NS_E_WMX_INVALID_FORMAT_OVER_NESTING", "message":"Windows Media Player cannot play the file because the associated playlist contains too many nested playlists."},

0xC00D107C: { "code": "NS_E_WMPCORE_NOSOURCEURLSTRING", "message":"Windows Media Player cannot find the file. Verify that the path is typed correctly. If it is, the file might not exist in the specified location, or the computer where the file is stored might not be available."},

0xC00D107D: { "code": "NS_E_WMPCORE_COCREATEFAILEDFORGITOBJECT", "message":"Failed to create the Global Interface Table."},

0xC00D107E: { "code": "NS_E_WMPCORE_FAILEDTOGETMARSHALLEDEVENTHANDLERINTERFACE", "message":"Failed to get the marshaled graph event handler interface."},

0xC00D107F: { "code": "NS_E_WMPCORE_BUFFERTOOSMALL", "message":"Buffer is too small for copying media type."},

0xC00D1080: { "code": "NS_E_WMPCORE_UNAVAILABLE", "message":"The current state of the Player does not allow this operation."},

0xC00D1081: { "code": "NS_E_WMPCORE_INVALIDPLAYLISTMODE", "message":"The playlist manager does not understand the current play mode (for example, shuffle or normal)."},

0xC00D1086: { "code": "NS_E_WMPCORE_ITEMNOTINPLAYLIST", "message":"Windows Media Player cannot play the file because it is not in the current playlist."},

0xC00D1087: { "code": "NS_E_WMPCORE_PLAYLISTEMPTY", "message":"There are no items in the playlist. Add items to the playlist, and then try again."},

0xC00D1088: { "code": "NS_E_WMPCORE_NOBROWSER", "message":"The web page cannot be displayed because no web browser is installed on your computer."},

0xC00D1089: { "code": "NS_E_WMPCORE_UNRECOGNIZED_MEDIA_URL", "message":"Windows Media Player cannot find the specified file. Verify the path is typed correctly. If it is, the file does not exist in the specified location, or the computer where the file is stored is not available."},

0xC00D108A: { "code": "NS_E_WMPCORE_GRAPH_NOT_IN_LIST", "message":"Graph with the specified URL was not found in the prerolled graph list."},

0xC00D108B: { "code": "NS_E_WMPCORE_PLAYLIST_EMPTY_OR_SINGLE_MEDIA", "message":"Windows Media Player cannot perform the requested operation because there is only one item in the playlist."},

0xC00D108C: { "code": "NS_E_WMPCORE_ERRORSINKNOTREGISTERED", "message":"An error sink was never registered for the calling object."},

0xC00D108D: { "code": "NS_E_WMPCORE_ERRORMANAGERNOTAVAILABLE", "message":"The error manager is not available to respond to errors."},

0xC00D108E: { "code": "NS_E_WMPCORE_WEBHELPFAILED", "message":"The Web Help URL cannot be opened."},

0xC00D108F: { "code": "NS_E_WMPCORE_MEDIA_ERROR_RESUME_FAILED", "message":"Could not resume playing next item in playlist."},

0xC00D1090: { "code": "NS_E_WMPCORE_NO_REF_IN_ENTRY", "message":"Windows Media Player cannot play the file because the associated playlist does not contain any items or the playlist is not valid."},

0xC00D1091: { "code": "NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_NAME_EMPTY", "message":"An empty string for playlist attribute name was found."},

0xC00D1092: { "code": "NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_NAME_ILLEGAL", "message":"A playlist attribute name that is not valid was found."},

0xC00D1093: { "code": "NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_VALUE_EMPTY", "message":"An empty string for a playlist attribute value was found."},

0xC00D1094: { "code": "NS_E_WMPCORE_WMX_LIST_ATTRIBUTE_VALUE_ILLEGAL", "message":"An illegal value for a playlist attribute was found."},

0xC00D1095: { "code": "NS_E_WMPCORE_WMX_LIST_ITEM_ATTRIBUTE_NAME_EMPTY", "message":"An empty string for a playlist item attribute name was found."},

0xC00D1096: { "code": "NS_E_WMPCORE_WMX_LIST_ITEM_ATTRIBUTE_NAME_ILLEGAL", "message":"An illegal value for a playlist item attribute name was found."},

0xC00D1097: { "code": "NS_E_WMPCORE_WMX_LIST_ITEM_ATTRIBUTE_VALUE_EMPTY", "message":"An illegal value for a playlist item attribute was found."},

0xC00D1098: { "code": "NS_E_WMPCORE_LIST_ENTRY_NO_REF", "message":"The playlist does not contain any items."},

0xC00D1099: { "code": "NS_E_WMPCORE_MISNAMED_FILE", "message":"Windows Media Player cannot play the file. The file is either corrupted or the Player does not support the format you are trying to play."},

0xC00D109A: { "code": "NS_E_WMPCORE_CODEC_NOT_TRUSTED", "message":"The codec downloaded for this file does not appear to be properly signed, so it cannot be installed."},

0xC00D109B: { "code": "NS_E_WMPCORE_CODEC_NOT_FOUND", "message":"Windows Media Player cannot play the file. One or more codecs required to play the file could not be found."},

0xC00D109C: { "code": "NS_E_WMPCORE_CODEC_DOWNLOAD_NOT_ALLOWED", "message":"Windows Media Player cannot play the file because a required codec is not installed on your computer. To try downloading the codec, turn on the \"Download codecs automatically\" option."},

0xC00D109D: { "code": "NS_E_WMPCORE_ERROR_DOWNLOADING_PLAYLIST", "message":"Windows Media Player encountered a problem while downloading the playlist. For additional assistance, click Web Help."},

0xC00D109E: { "code": "NS_E_WMPCORE_FAILED_TO_BUILD_PLAYLIST", "message":"Failed to build the playlist."},

0xC00D109F: { "code": "NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_NONE", "message":"Playlist has no alternates to switch into."},

0xC00D10A0: { "code": "NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_EXHAUSTED", "message":"No more playlist alternates available to switch to."},

0xC00D10A1: { "code": "NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_NAME_NOT_FOUND", "message":"Could not find the name of the alternate playlist to switch into."},

0xC00D10A2: { "code": "NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_MORPH_FAILED", "message":"Failed to switch to an alternate for this media."},

0xC00D10A3: { "code": "NS_E_WMPCORE_PLAYLIST_ITEM_ALTERNATE_INIT_FAILED", "message":"Failed to initialize an alternate for the media."},

0xC00D10A4: { "code": "NS_E_WMPCORE_MEDIA_ALTERNATE_REF_EMPTY", "message":"No URL specified for the roll over Refs in the playlist file."},

0xC00D10A5: { "code": "NS_E_WMPCORE_PLAYLIST_NO_EVENT_NAME", "message":"Encountered a playlist with no name."},

0xC00D10A6: { "code": "NS_E_WMPCORE_PLAYLIST_EVENT_ATTRIBUTE_ABSENT", "message":"A required attribute in the event block of the playlist was not found."},

0xC00D10A7: { "code": "NS_E_WMPCORE_PLAYLIST_EVENT_EMPTY", "message":"No items were found in the event block of the playlist."},

0xC00D10A8: { "code": "NS_E_WMPCORE_PLAYLIST_STACK_EMPTY", "message":"No playlist was found while returning from a nested playlist."},

0xC00D10A9: { "code": "NS_E_WMPCORE_CURRENT_MEDIA_NOT_ACTIVE", "message":"The media item is not active currently."},

0xC00D10AB: { "code": "NS_E_WMPCORE_USER_CANCEL", "message":"Windows Media Player cannot perform the requested action because you chose to cancel it."},

0xC00D10AC: { "code": "NS_E_WMPCORE_PLAYLIST_REPEAT_EMPTY", "message":"Windows Media Player encountered a problem with the playlist. The format of the playlist is not valid."},

0xC00D10AD: { "code": "NS_E_WMPCORE_PLAYLIST_REPEAT_START_MEDIA_NONE", "message":"Media object corresponding to start of a playlist repeat block was not found."},

0xC00D10AE: { "code": "NS_E_WMPCORE_PLAYLIST_REPEAT_END_MEDIA_NONE", "message":"Media object corresponding to the end of a playlist repeat block was not found."},

0xC00D10AF: { "code": "NS_E_WMPCORE_INVALID_PLAYLIST_URL", "message":"The playlist URL supplied to the playlist manager is not valid."},

0xC00D10B0: { "code": "NS_E_WMPCORE_MISMATCHED_RUNTIME", "message":"Windows Media Player cannot play the file because it is corrupted."},

0xC00D10B1: { "code": "NS_E_WMPCORE_PLAYLIST_IMPORT_FAILED_NO_ITEMS", "message":"Windows Media Player cannot add the playlist to the library because the playlist does not contain any items."},

0xC00D10B2: { "code": "NS_E_WMPCORE_VIDEO_TRANSFORM_FILTER_INSERTION", "message":"An error has occurred that could prevent the changing of the video contrast on this media."},

0xC00D10B3: { "code": "NS_E_WMPCORE_MEDIA_UNAVAILABLE", "message":"Windows Media Player cannot play the file. If the file is located on the Internet, connect to the Internet. If the file is located on a removable storage card, insert the storage card."},

0xC00D10B4: { "code": "NS_E_WMPCORE_WMX_ENTRYREF_NO_REF", "message":"The playlist contains an ENTRYREF for which no href was parsed. Check the syntax of playlist file."},

0xC00D10B5: { "code": "NS_E_WMPCORE_NO_PLAYABLE_MEDIA_IN_PLAYLIST", "message":"Windows Media Player cannot play any items in the playlist. To find information about the problem, click the Now Playing tab, and then click the icon next to each file in the List pane."},

0xC00D10B6: { "code": "NS_E_WMPCORE_PLAYLIST_EMPTY_NESTED_PLAYLIST_SKIPPED_ITEMS", "message":"Windows Media Player cannot play some or all of the items in the playlist because the playlist is nested."},

0xC00D10B7: { "code": "NS_E_WMPCORE_BUSY", "message":"Windows Media Player cannot play the file at this time. Try again later."},

0xC00D10B8: { "code": "NS_E_WMPCORE_MEDIA_CHILD_PLAYLIST_UNAVAILABLE", "message":"There is no child playlist available for this media item at this time."},

0xC00D10B9: { "code": "NS_E_WMPCORE_MEDIA_NO_CHILD_PLAYLIST", "message":"There is no child playlist for this media item."},

0xC00D10BA: { "code": "NS_E_WMPCORE_FILE_NOT_FOUND", "message":"Windows Media Player cannot find the file. The link from the item in the library to its associated digital media file might be broken. To fix the problem, try repairing the link or removing the item from the library."},

0xC00D10BB: { "code": "NS_E_WMPCORE_TEMP_FILE_NOT_FOUND", "message":"The temporary file was not found."},

0xC00D10BC: { "code": "NS_E_WMDM_REVOKED", "message":"Windows Media Player cannot sync the file because the device needs to be updated."},

0xC00D10BD: { "code": "NS_E_DDRAW_GENERIC", "message":"Windows Media Player cannot play the video because there is a problem with your video card."},

0xC00D10BE: { "code": "NS_E_DISPLAY_MODE_CHANGE_FAILED", "message":"Windows Media Player failed to change the screen mode for full-screen video playback."},

0xC00D10BF: { "code": "NS_E_PLAYLIST_CONTAINS_ERRORS", "message":"Windows Media Player cannot play one or more files. For additional information, right-click an item that cannot be played, and then click Error Details."},

0xC00D10C0: { "code": "NS_E_CHANGING_PROXY_NAME", "message":"Cannot change the proxy name if the proxy setting is not set to custom."},

0xC00D10C1: { "code": "NS_E_CHANGING_PROXY_PORT", "message":"Cannot change the proxy port if the proxy setting is not set to custom."},

0xC00D10C2: { "code": "NS_E_CHANGING_PROXY_EXCEPTIONLIST", "message":"Cannot change the proxy exception list if the proxy setting is not set to custom."},

0xC00D10C3: { "code": "NS_E_CHANGING_PROXYBYPASS", "message":"Cannot change the proxy bypass flag if the proxy setting is not set to custom."},

0xC00D10C4: { "code": "NS_E_CHANGING_PROXY_PROTOCOL_NOT_FOUND", "message":"Cannot find the specified protocol."},

0xC00D10C5: { "code": "NS_E_GRAPH_NOAUDIOLANGUAGE", "message":"Cannot change the language settings. Either the graph has no audio or the audio only supports one language."},

0xC00D10C6: { "code": "NS_E_GRAPH_NOAUDIOLANGUAGESELECTED", "message":"The graph has no audio language selected."},

0xC00D10C7: { "code": "NS_E_CORECD_NOTAMEDIACD", "message":"This is not a media CD."},

0xC00D10C8: { "code": "NS_E_WMPCORE_MEDIA_URL_TOO_LONG", "message":"Windows Media Player cannot play the file because the URL is too long."},

0xC00D10C9: { "code": "NS_E_WMPFLASH_CANT_FIND_COM_SERVER", "message":"To play the selected item, you must install the Macromedia Flash Player. To download the Macromedia Flash Player, go to the Adobe website."},

0xC00D10CA: { "code": "NS_E_WMPFLASH_INCOMPATIBLEVERSION", "message":"To play the selected item, you must install a later version of the Macromedia Flash Player. To download the Macromedia Flash Player, go to the Adobe website."},

0xC00D10CB: { "code": "NS_E_WMPOCXGRAPH_IE_DISALLOWS_ACTIVEX_CONTROLS", "message":"Windows Media Player cannot play the file because your Internet security settings prohibit the use of ActiveX controls."},

0xC00D10CC: { "code": "NS_E_NEED_CORE_REFERENCE", "message":"The use of this method requires an existing reference to the Player object."},

0xC00D10CD: { "code": "NS_E_MEDIACD_READ_ERROR", "message":"Windows Media Player cannot play the CD. The disc might be dirty or damaged."},

0xC00D10CE: { "code": "NS_E_IE_DISALLOWS_ACTIVEX_CONTROLS", "message":"Windows Media Player cannot play the file because your Internet security settings prohibit the use of ActiveX controls."},

0xC00D10CF: { "code": "NS_E_FLASH_PLAYBACK_NOT_ALLOWED", "message":"Flash playback has been turned off in Windows Media Player."},

0xC00D10D0: { "code": "NS_E_UNABLE_TO_CREATE_RIP_LOCATION", "message":"Windows Media Player cannot rip the CD because a valid rip location cannot be created."},

0xC00D10D1: { "code": "NS_E_WMPCORE_SOME_CODECS_MISSING", "message":"Windows Media Player cannot play the file because a required codec is not installed on your computer."},

0xC00D10D2: { "code": "NS_E_WMP_RIP_FAILED", "message":"Windows Media Player cannot rip one or more tracks from the CD."},

0xC00D10D3: { "code": "NS_E_WMP_FAILED_TO_RIP_TRACK", "message":"Windows Media Player encountered a problem while ripping the track from the CD. For additional assistance, click Web Help."},

0xC00D10D4: { "code": "NS_E_WMP_ERASE_FAILED", "message":"Windows Media Player encountered a problem while erasing the disc. For additional assistance, click Web Help."},

0xC00D10D5: { "code": "NS_E_WMP_FORMAT_FAILED", "message":"Windows Media Player encountered a problem while formatting the device. For additional assistance, click Web Help."},

0xC00D10D6: { "code": "NS_E_WMP_CANNOT_BURN_NON_LOCAL_FILE", "message":"This file cannot be burned to a CD because it is not located on your computer."},

0xC00D10D7: { "code": "NS_E_WMP_FILE_TYPE_CANNOT_BURN_TO_AUDIO_CD", "message":"It is not possible to burn this file type to an audio CD. Windows Media Player can burn the following file types to an audio CD: WMA, MP3, or WAV."},

0xC00D10D8: { "code": "NS_E_WMP_FILE_DOES_NOT_FIT_ON_CD", "message":"This file is too large to fit on a disc."},

0xC00D10D9: { "code": "NS_E_WMP_FILE_NO_DURATION", "message":"It is not possible to determine if this file can fit on a disc because Windows Media Player cannot detect the length of the file. Playing the file before burning might enable the Player to detect the file length."},

0xC00D10DA: { "code": "NS_E_PDA_FAILED_TO_BURN", "message":"Windows Media Player encountered a problem while burning the file to the disc. For additional assistance, click Web Help."},

0xC00D10DC: { "code": "NS_E_FAILED_DOWNLOAD_ABORT_BURN", "message":"Windows Media Player cannot burn the audio CD because some items in the list that you chose to buy could not be downloaded from the online store."},

0xC00D10DD: { "code": "NS_E_WMPCORE_DEVICE_DRIVERS_MISSING", "message":"Windows Media Player cannot play the file. Try using Windows Update or Device Manager to update the device drivers for your audio and video cards. For information about using Windows Update or Device Manager, see Windows Help."},

0xC00D1126: { "code": "NS_E_WMPIM_USEROFFLINE", "message":"Windows Media Player has detected that you are not connected to the Internet. Connect to the Internet, and then try again."},

0xC00D1127: { "code": "NS_E_WMPIM_USERCANCELED", "message":"The attempt to connect to the Internet was canceled."},

0xC00D1128: { "code": "NS_E_WMPIM_DIALUPFAILED", "message":"The attempt to connect to the Internet failed."},

0xC00D1129: { "code": "NS_E_WINSOCK_ERROR_STRING", "message":"Windows Media Player has encountered an unknown network error."},

0xC00D1130: { "code": "NS_E_WMPBR_NOLISTENER", "message":"No window is currently listening to Backup and Restore events."},

0xC00D1131: { "code": "NS_E_WMPBR_BACKUPCANCEL", "message":"Your media usage rights were not backed up because the backup was canceled."},

0xC00D1132: { "code": "NS_E_WMPBR_RESTORECANCEL", "message":"Your media usage rights were not restored because the restoration was canceled."},

0xC00D1133: { "code": "NS_E_WMPBR_ERRORWITHURL", "message":"An error occurred while backing up or restoring your media usage rights. A required web page cannot be displayed."},

0xC00D1134: { "code": "NS_E_WMPBR_NAMECOLLISION", "message":"Your media usage rights were not backed up because the backup was canceled."},

0xC00D1137: { "code": "NS_E_WMPBR_DRIVE_INVALID", "message":"Windows Media Player cannot restore your media usage rights from the specified location. Choose another location, and then try again."},

0xC00D1138: { "code": "NS_E_WMPBR_BACKUPRESTOREFAILED", "message":"Windows Media Player cannot backup or restore your media usage rights."},

0xC00D1158: { "code": "NS_E_WMP_CONVERT_FILE_FAILED", "message":"Windows Media Player cannot add the file to the library."},

0xC00D1159: { "code": "NS_E_WMP_CONVERT_NO_RIGHTS_ERRORURL", "message":"Windows Media Player cannot add the file to the library because the content provider prohibits it. For assistance, contact the company that provided the file."},

0xC00D115A: { "code": "NS_E_WMP_CONVERT_NO_RIGHTS_NOERRORURL", "message":"Windows Media Player cannot add the file to the library because the content provider prohibits it. For assistance, contact the company that provided the file."},

0xC00D115B: { "code": "NS_E_WMP_CONVERT_FILE_CORRUPT", "message":"Windows Media Player cannot add the file to the library. The file might not be valid."},

0xC00D115C: { "code": "NS_E_WMP_CONVERT_PLUGIN_UNAVAILABLE_ERRORURL", "message":"Windows Media Player cannot add the file to the library. The plug-in required to add the file is not installed properly. For assistance, click Web Help to display the website of the company that provided the file."},

0xC00D115D: { "code": "NS_E_WMP_CONVERT_PLUGIN_UNAVAILABLE_NOERRORURL", "message":"Windows Media Player cannot add the file to the library. The plug-in required to add the file is not installed properly. For assistance, contact the company that provided the file."},

0xC00D115E: { "code": "NS_E_WMP_CONVERT_PLUGIN_UNKNOWN_FILE_OWNER", "message":"Windows Media Player cannot add the file to the library. The plug-in required to add the file is not installed properly. For assistance, contact the company that provided the file."},

0xC00D1160: { "code": "NS_E_DVD_DISC_COPY_PROTECT_OUTPUT_NS", "message":"Windows Media Player cannot play this DVD. Try installing an updated driver for your video card or obtaining a newer video card."},

0xC00D1161: { "code": "NS_E_DVD_DISC_COPY_PROTECT_OUTPUT_FAILED", "message":"This DVD's resolution exceeds the maximum allowed by your component video outputs. Try reducing your screen resolution to 640 x 480, or turn off analog component outputs and use a VGA connection to your monitor."},

0xC00D1162: { "code": "NS_E_DVD_NO_SUBPICTURE_STREAM", "message":"Windows Media Player cannot display subtitles or highlights in DVD menus. Reinstall the DVD decoder or contact the DVD drive manufacturer to obtain an updated decoder."},

0xC00D1163: { "code": "NS_E_DVD_COPY_PROTECT", "message":"Windows Media Player cannot play this DVD because there is a problem with digital copy protection between your DVD drive, decoder, and video card. Try installing an updated driver for your video card."},

0xC00D1164: { "code": "NS_E_DVD_AUTHORING_PROBLEM", "message":"Windows Media Player cannot play the DVD. The disc was created in a manner that the Player does not support."},

0xC00D1165: { "code": "NS_E_DVD_INVALID_DISC_REGION", "message":"Windows Media Player cannot play the DVD because the disc prohibits playback in your region of the world. You must obtain a disc that is intended for your geographic region."},

0xC00D1166: { "code": "NS_E_DVD_COMPATIBLE_VIDEO_CARD", "message":"Windows Media Player cannot play the DVD because your video card does not support DVD playback."},

0xC00D1167: { "code": "NS_E_DVD_MACROVISION", "message":"Windows Media Player cannot play this DVD because it is not possible to turn on analog copy protection on the output display. Try installing an updated driver for your video card."},

0xC00D1168: { "code": "NS_E_DVD_SYSTEM_DECODER_REGION", "message":"Windows Media Player cannot play the DVD because the region assigned to your DVD drive does not match the region assigned to your DVD decoder."},

0xC00D1169: { "code": "NS_E_DVD_DISC_DECODER_REGION", "message":"Windows Media Player cannot play the DVD because the disc prohibits playback in your region of the world. You must obtain a disc that is intended for your geographic region."},

0xC00D116A: { "code": "NS_E_DVD_NO_VIDEO_STREAM", "message":"Windows Media Player cannot play DVD video. You might need to adjust your Windows display settings. Open display settings in Control Panel, and then try lowering your screen resolution and color quality settings."},

0xC00D116B: { "code": "NS_E_DVD_NO_AUDIO_STREAM", "message":"Windows Media Player cannot play DVD audio. Verify that your sound card is set up correctly, and then try again."},

0xC00D116C: { "code": "NS_E_DVD_GRAPH_BUILDING", "message":"Windows Media Player cannot play DVD video. Close any open files and quit any other programs, and then try again. If the problem persists, restart your computer."},

0xC00D116D: { "code": "NS_E_DVD_NO_DECODER", "message":"Windows Media Player cannot play the DVD because a compatible DVD decoder is not installed on your computer."},

0xC00D116E: { "code": "NS_E_DVD_PARENTAL", "message":"Windows Media Player cannot play the scene because it has a parental rating higher than the rating that you are authorized to view."},

0xC00D116F: { "code": "NS_E_DVD_CANNOT_JUMP", "message":"Windows Media Player cannot skip to the requested location on the DVD."},

0xC00D1170: { "code": "NS_E_DVD_DEVICE_CONTENTION", "message":"Windows Media Player cannot play the DVD because it is currently in use by another program. Quit the other program that is using the DVD, and then try again."},

0xC00D1171: { "code": "NS_E_DVD_NO_VIDEO_MEMORY", "message":"Windows Media Player cannot play DVD video. You might need to adjust your Windows display settings. Open display settings in Control Panel, and then try lowering your screen resolution and color quality settings."},

0xC00D1172: { "code": "NS_E_DVD_CANNOT_COPY_PROTECTED", "message":"Windows Media Player cannot rip the DVD because it is copy protected."},

0xC00D1173: { "code": "NS_E_DVD_REQUIRED_PROPERTY_NOT_SET", "message":"One of more of the required properties has not been set."},

0xC00D1174: { "code": "NS_E_DVD_INVALID_TITLE_CHAPTER", "message":"The specified title and/or chapter number does not exist on this DVD."},

0xC00D1176: { "code": "NS_E_NO_CD_BURNER", "message":"Windows Media Player cannot burn the files because the Player cannot find a burner. If the burner is connected properly, try using Windows Update to install the latest device driver."},

0xC00D1177: { "code": "NS_E_DEVICE_IS_NOT_READY", "message":"Windows Media Player does not detect storage media in the selected device. Insert storage media into the device, and then try again."},

0xC00D1178: { "code": "NS_E_PDA_UNSUPPORTED_FORMAT", "message":"Windows Media Player cannot sync this file. The Player might not support the file type."},

0xC00D1179: { "code": "NS_E_NO_PDA", "message":"Windows Media Player does not detect a portable device. Connect your portable device, and then try again."},

0xC00D117A: { "code": "NS_E_PDA_UNSPECIFIED_ERROR", "message":"Windows Media Player encountered an error while communicating with the device. The storage card on the device might be full, the device might be turned off, or the device might not allow playlists or folders to be created on it."},

0xC00D117B: { "code": "NS_E_MEMSTORAGE_BAD_DATA", "message":"Windows Media Player encountered an error while burning a CD."},

0xC00D117C: { "code": "NS_E_PDA_FAIL_SELECT_DEVICE", "message":"Windows Media Player encountered an error while communicating with a portable device or CD drive."},

0xC00D117D: { "code": "NS_E_PDA_FAIL_READ_WAVE_FILE", "message":"Windows Media Player cannot open the WAV file."},

0xC00D117E: { "code": "NS_E_IMAPI_LOSSOFSTREAMING", "message":"Windows Media Player failed to burn all the files to the CD. Select a slower recording speed, and then try again."},

0xC00D117F: { "code": "NS_E_PDA_DEVICE_FULL", "message":"There is not enough storage space on the portable device to complete this operation. Delete some unneeded files on the portable device, and then try again."},

0xC00D1180: { "code": "NS_E_FAIL_LAUNCH_ROXIO_PLUGIN", "message":"Windows Media Player cannot burn the files. Verify that your burner is connected properly, and then try again. If the problem persists, reinstall the Player."},

0xC00D1181: { "code": "NS_E_PDA_DEVICE_FULL_IN_SESSION", "message":"Windows Media Player did not sync some files to the device because there is not enough storage space on the device."},

0xC00D1182: { "code": "NS_E_IMAPI_MEDIUM_INVALIDTYPE", "message":"The disc in the burner is not valid. Insert a blank disc into the burner, and then try again."},

0xC00D1183: { "code": "NS_E_PDA_MANUALDEVICE", "message":"Windows Media Player cannot perform the requested action because the device does not support sync."},

0xC00D1184: { "code": "NS_E_PDA_PARTNERSHIPNOTEXIST", "message":"To perform the requested action, you must first set up sync with the device."},

0xC00D1185: { "code": "NS_E_PDA_CANNOT_CREATE_ADDITIONAL_SYNC_RELATIONSHIP", "message":"You have already created sync partnerships with 16 devices. To create a new sync partnership, you must first end an existing partnership."},

0xC00D1186: { "code": "NS_E_PDA_NO_TRANSCODE_OF_DRM", "message":"Windows Media Player cannot sync the file because protected files cannot be converted to the required quality level or file format."},

0xC00D1187: { "code": "NS_E_PDA_TRANSCODECACHEFULL", "message":"The folder that stores converted files is full. Either empty the folder or increase its size, and then try again."},

0xC00D1188: { "code": "NS_E_PDA_TOO_MANY_FILE_COLLISIONS", "message":"There are too many files with the same name in the folder on the device. Change the file name or sync to a different folder."},

0xC00D1189: { "code": "NS_E_PDA_CANNOT_TRANSCODE", "message":"Windows Media Player cannot convert the file to the format required by the device."},

0xC00D118A: { "code": "NS_E_PDA_TOO_MANY_FILES_IN_DIRECTORY", "message":"You have reached the maximum number of files your device allows in a folder. If your device supports playback from subfolders, try creating subfolders on the device and storing some files in them."},

0xC00D118B: { "code": "NS_E_PROCESSINGSHOWSYNCWIZARD", "message":"Windows Media Player is already trying to start the Device Setup Wizard."},

0xC00D118C: { "code": "NS_E_PDA_TRANSCODE_NOT_PERMITTED", "message":"Windows Media Player cannot convert this file format. If an updated version of the codec used to compress this file is available, install it and then try to sync the file again."},

0xC00D118D: { "code": "NS_E_PDA_INITIALIZINGDEVICES", "message":"Windows Media Player is busy setting up devices. Try again later."},

0xC00D118E: { "code": "NS_E_PDA_OBSOLETE_SP", "message":"Your device is using an outdated driver that is no longer supported by Windows Media Player. For additional assistance, click Web Help."},

0xC00D118F: { "code": "NS_E_PDA_TITLE_COLLISION", "message":"Windows Media Player cannot sync the file because a file with the same name already exists on the device. Change the file name or try to sync the file to a different folder."},

0xC00D1190: { "code": "NS_E_PDA_DEVICESUPPORTDISABLED", "message":"Automatic and manual sync have been turned off temporarily. To sync to a device, restart Windows Media Player."},

0xC00D1191: { "code": "NS_E_PDA_NO_LONGER_AVAILABLE", "message":"This device is not available. Connect the device to the computer, and then try again."},

0xC00D1192: { "code": "NS_E_PDA_ENCODER_NOT_RESPONDING", "message":"Windows Media Player cannot sync the file because an error occurred while converting the file to another quality level or format. If the problem persists, remove the file from the list of files to sync."},

0xC00D1193: { "code": "NS_E_PDA_CANNOT_SYNC_FROM_LOCATION", "message":"Windows Media Player cannot sync the file to your device. The file might be stored in a location that is not supported. Copy the file from its current location to your hard disk, add it to your library, and then try to sync the file again."},

0xC00D1194: { "code": "NS_E_WMP_PROTOCOL_PROBLEM", "message":"Windows Media Player cannot open the specified URL. Verify that the Player is configured to use all available protocols, and then try again."},

0xC00D1195: { "code": "NS_E_WMP_NO_DISK_SPACE", "message":"Windows Media Player cannot perform the requested action because there is not enough storage space on your computer. Delete some unneeded files on your hard disk, and then try again."},

0xC00D1196: { "code": "NS_E_WMP_LOGON_FAILURE", "message":"The server denied access to the file. Verify that you are using the correct user name and password."},

0xC00D1197: { "code": "NS_E_WMP_CANNOT_FIND_FILE", "message":"Windows Media Player cannot find the file. If you are trying to play, burn, or sync an item that is in your library, the item might point to a file that has been moved, renamed, or deleted."},

0xC00D1198: { "code": "NS_E_WMP_SERVER_INACCESSIBLE", "message":"Windows Media Player cannot connect to the server. The server name might not be correct, the server might not be available, or your proxy settings might not be correct."},

0xC00D1199: { "code": "NS_E_WMP_UNSUPPORTED_FORMAT", "message":"Windows Media Player cannot play the file. The Player might not support the file type or might not support the codec that was used to compress the file."},

0xC00D119A: { "code": "NS_E_WMP_DSHOW_UNSUPPORTED_FORMAT", "message":"Windows Media Player cannot play the file. The Player might not support the file type or a required codec might not be installed on your computer."},

0xC00D119B: { "code": "NS_E_WMP_PLAYLIST_EXISTS", "message":"Windows Media Player cannot create the playlist because the name already exists. Type a different playlist name."},

0xC00D119C: { "code": "NS_E_WMP_NONMEDIA_FILES", "message":"Windows Media Player cannot delete the playlist because it contains items that are not digital media files. Any digital media files in the playlist were deleted."},

0xC00D119D: { "code": "NS_E_WMP_INVALID_ASX", "message":"The playlist cannot be opened because it is stored in a shared folder on another computer. If possible, move the playlist to the playlists folder on your computer."},

0xC00D119E: { "code": "NS_E_WMP_ALREADY_IN_USE", "message":"Windows Media Player is already in use. Stop playing any items, close all Player dialog boxes, and then try again."},

0xC00D119F: { "code": "NS_E_WMP_IMAPI_FAILURE", "message":"Windows Media Player encountered an error while burning. Verify that the burner is connected properly and that the disc is clean and not damaged."},

0xC00D11A0: { "code": "NS_E_WMP_WMDM_FAILURE", "message":"Windows Media Player has encountered an unknown error with your portable device. Reconnect your portable device, and then try again."},

0xC00D11A1: { "code": "NS_E_WMP_CODEC_NEEDED_WITH_4CC", "message":"A codec is required to play this file. To determine if this codec is available to download from the web, click Web Help."},

0xC00D11A2: { "code": "NS_E_WMP_CODEC_NEEDED_WITH_FORMATTAG", "message":"An audio codec is needed to play this file. To determine if this codec is available to download from the web, click Web Help."},

0xC00D11A3: { "code": "NS_E_WMP_MSSAP_NOT_AVAILABLE", "message":"To play the file, you must install the latest Windows service pack. To install the service pack from the Windows Update website, click Web Help."},

0xC00D11A4: { "code": "NS_E_WMP_WMDM_INTERFACEDEAD", "message":"Windows Media Player no longer detects a portable device. Reconnect your portable device, and then try again."},

0xC00D11A5: { "code": "NS_E_WMP_WMDM_NOTCERTIFIED", "message":"Windows Media Player cannot sync the file because the portable device does not support protected files."},

0xC00D11A6: { "code": "NS_E_WMP_WMDM_LICENSE_NOTEXIST", "message":"This file does not have sync rights. If you obtained this file from an online store, go to the online store to get sync rights."},

0xC00D11A7: { "code": "NS_E_WMP_WMDM_LICENSE_EXPIRED", "message":"Windows Media Player cannot sync the file because the sync rights have expired. Go to the content provider's online store to get new sync rights."},

0xC00D11A8: { "code": "NS_E_WMP_WMDM_BUSY", "message":"The portable device is already in use. Wait until the current task finishes or quit other programs that might be using the portable device, and then try again."},

0xC00D11A9: { "code": "NS_E_WMP_WMDM_NORIGHTS", "message":"Windows Media Player cannot sync the file because the content provider or device prohibits it. You might be able to resolve this problem by going to the content provider's online store to get sync rights."},

0xC00D11AA: { "code": "NS_E_WMP_WMDM_INCORRECT_RIGHTS", "message":"The content provider has not granted you the right to sync this file. Go to the content provider's online store to get sync rights."},

0xC00D11AB: { "code": "NS_E_WMP_IMAPI_GENERIC", "message":"Windows Media Player cannot burn the files to the CD. Verify that the disc is clean and not damaged. If necessary, select a slower recording speed or try a different brand of blank discs."},

0xC00D11AD: { "code": "NS_E_WMP_IMAPI_DEVICE_NOTPRESENT", "message":"Windows Media Player cannot burn the files. Verify that the burner is connected properly, and then try again."},

0xC00D11AE: { "code": "NS_E_WMP_IMAPI_DEVICE_BUSY", "message":"Windows Media Player cannot burn the files. Verify that the burner is connected properly and that the disc is clean and not damaged. If the burner is already in use, wait until the current task finishes or quit other programs that might be using the burner."},

0xC00D11AF: { "code": "NS_E_WMP_IMAPI_LOSS_OF_STREAMING", "message":"Windows Media Player cannot burn the files to the CD."},

0xC00D11B0: { "code": "NS_E_WMP_SERVER_UNAVAILABLE", "message":"Windows Media Player cannot play the file. The server might not be available or there might be a problem with your network or firewall settings."},

0xC00D11B1: { "code": "NS_E_WMP_FILE_OPEN_FAILED", "message":"Windows Media Player encountered a problem while playing the file. For additional assistance, click Web Help."},

0xC00D11B2: { "code": "NS_E_WMP_VERIFY_ONLINE", "message":"Windows Media Player must connect to the Internet to verify the file's media usage rights. Connect to the Internet, and then try again."},

0xC00D11B3: { "code": "NS_E_WMP_SERVER_NOT_RESPONDING", "message":"Windows Media Player cannot play the file because a network error occurred. The server might not be available. Verify that you are connected to the network and that your proxy settings are correct."},

0xC00D11B4: { "code": "NS_E_WMP_DRM_CORRUPT_BACKUP", "message":"Windows Media Player cannot restore your media usage rights because it could not find any backed up rights on your computer."},

0xC00D11B5: { "code": "NS_E_WMP_DRM_LICENSE_SERVER_UNAVAILABLE", "message":"Windows Media Player cannot download media usage rights because the server is not available (for example, the server might be busy or not online)."},

0xC00D11B6: { "code": "NS_E_WMP_NETWORK_FIREWALL", "message":"Windows Media Player cannot play the file. A network firewall might be preventing the Player from opening the file by using the UDP transport protocol. If you typed a URL in the Open URL dialog box, try using a different transport protocol (for example, \"http:\")."},

0xC00D11B7: { "code": "NS_E_WMP_NO_REMOVABLE_MEDIA", "message":"Insert the removable media, and then try again."},

0xC00D11B8: { "code": "NS_E_WMP_PROXY_CONNECT_TIMEOUT", "message":"Windows Media Player cannot play the file because the proxy server is not responding. The proxy server might be temporarily unavailable or your Player proxy settings might not be valid."},

0xC00D11B9: { "code": "NS_E_WMP_NEED_UPGRADE", "message":"To play the file, you might need to install a later version of Windows Media Player. On the Help menu, click Check for Updates, and then follow the instructions. For additional assistance, click Web Help."},

0xC00D11BA: { "code": "NS_E_WMP_AUDIO_HW_PROBLEM", "message":"Windows Media Player cannot play the file because there is a problem with your sound device. There might not be a sound device installed on your computer, it might be in use by another program, or it might not be functioning properly."},

0xC00D11BB: { "code": "NS_E_WMP_INVALID_PROTOCOL", "message":"Windows Media Player cannot play the file because the specified protocol is not supported. If you typed a URL in the Open URL dialog box, try using a different transport protocol (for example, \"http:\" or \"rtsp:\")."},

0xC00D11BC: { "code": "NS_E_WMP_INVALID_LIBRARY_ADD", "message":"Windows Media Player cannot add the file to the library because the file format is not supported."},

0xC00D11BD: { "code": "NS_E_WMP_MMS_NOT_SUPPORTED", "message":"Windows Media Player cannot play the file because the specified protocol is not supported. If you typed a URL in the Open URL dialog box, try using a different transport protocol (for example, \"mms:\")."},

0xC00D11BE: { "code": "NS_E_WMP_NO_PROTOCOLS_SELECTED", "message":"Windows Media Player cannot play the file because there are no streaming protocols selected. Select one or more protocols, and then try again."},

0xC00D11BF: { "code": "NS_E_WMP_GOFULLSCREEN_FAILED", "message":"Windows Media Player cannot switch to Full Screen. You might need to adjust your Windows display settings. Open display settings in Control Panel, and then try setting Hardware acceleration to Full."},

0xC00D11C0: { "code": "NS_E_WMP_NETWORK_ERROR", "message":"Windows Media Player cannot play the file because a network error occurred. The server might not be available (for example, the server is busy or not online) or you might not be connected to the network."},

0xC00D11C1: { "code": "NS_E_WMP_CONNECT_TIMEOUT", "message":"Windows Media Player cannot play the file because the server is not responding. Verify that you are connected to the network, and then try again later."},

0xC00D11C2: { "code": "NS_E_WMP_MULTICAST_DISABLED", "message":"Windows Media Player cannot play the file because the multicast protocol is not enabled. On the Tools menu, click Options, click the Network tab, and then select the Multicast check box. For additional assistance, click Web Help."},

0xC00D11C3: { "code": "NS_E_WMP_SERVER_DNS_TIMEOUT", "message":"Windows Media Player cannot play the file because a network problem occurred. Verify that you are connected to the network, and then try again later."},

0xC00D11C4: { "code": "NS_E_WMP_PROXY_NOT_FOUND", "message":"Windows Media Player cannot play the file because the network proxy server cannot be found. Verify that your proxy settings are correct, and then try again."},

0xC00D11C5: { "code": "NS_E_WMP_TAMPERED_CONTENT", "message":"Windows Media Player cannot play the file because it is corrupted."},

0xC00D11C6: { "code": "NS_E_WMP_OUTOFMEMORY", "message":"Your computer is running low on memory. Quit other programs, and then try again."},

0xC00D11C7: { "code": "NS_E_WMP_AUDIO_CODEC_NOT_INSTALLED", "message":"Windows Media Player cannot play, burn, rip, or sync the file because a required audio codec is not installed on your computer."},

0xC00D11C8: { "code": "NS_E_WMP_VIDEO_CODEC_NOT_INSTALLED", "message":"Windows Media Player cannot play the file because the required video codec is not installed on your computer."},

0xC00D11C9: { "code": "NS_E_WMP_IMAPI_DEVICE_INVALIDTYPE", "message":"Windows Media Player cannot burn the files. If the burner is busy, wait for the current task to finish. If necessary, verify that the burner is connected properly and that you have installed the latest device driver."},

0xC00D11CA: { "code": "NS_E_WMP_DRM_DRIVER_AUTH_FAILURE", "message":"Windows Media Player cannot play the protected file because there is a problem with your sound device. Try installing a new device driver or use a different sound device."},

0xC00D11CB: { "code": "NS_E_WMP_NETWORK_RESOURCE_FAILURE", "message":"Windows Media Player encountered a network error. Restart the Player."},

0xC00D11CC: { "code": "NS_E_WMP_UPGRADE_APPLICATION", "message":"Windows Media Player is not installed properly. Reinstall the Player."},

0xC00D11CD: { "code": "NS_E_WMP_UNKNOWN_ERROR", "message":"Windows Media Player encountered an unknown error. For additional assistance, click Web Help."},

0xC00D11CE: { "code": "NS_E_WMP_INVALID_KEY", "message":"Windows Media Player cannot play the file because the required codec is not valid."},

0xC00D11CF: { "code": "NS_E_WMP_CD_ANOTHER_USER", "message":"The CD drive is in use by another user. Wait for the task to complete, and then try again."},

0xC00D11D0: { "code": "NS_E_WMP_DRM_NEEDS_AUTHORIZATION", "message":"Windows Media Player cannot play, sync, or burn the protected file because a problem occurred with the Windows Media Digital Rights Management (DRM) system. You might need to connect to the Internet to update your DRM components. For additional assistance, click Web Help."},

0xC00D11D1: { "code": "NS_E_WMP_BAD_DRIVER", "message":"Windows Media Player cannot play the file because there might be a problem with your sound or video device. Try installing an updated device driver."},

0xC00D11D2: { "code": "NS_E_WMP_ACCESS_DENIED", "message":"Windows Media Player cannot access the file. The file might be in use, you might not have access to the computer where the file is stored, or your proxy settings might not be correct."},

0xC00D11D3: { "code": "NS_E_WMP_LICENSE_RESTRICTS", "message":"The content provider prohibits this action. Go to the content provider's online store to get new media usage rights."},

0xC00D11D4: { "code": "NS_E_WMP_INVALID_REQUEST", "message":"Windows Media Player cannot perform the requested action at this time."},

0xC00D11D5: { "code": "NS_E_WMP_CD_STASH_NO_SPACE", "message":"Windows Media Player cannot burn the files because there is not enough free disk space to store the temporary files. Delete some unneeded files on your hard disk, and then try again."},

0xC00D11D6: { "code": "NS_E_WMP_DRM_NEW_HARDWARE", "message":"Your media usage rights have become corrupted or are no longer valid. This might happen if you have replaced hardware components in your computer."},

0xC00D11D7: { "code": "NS_E_WMP_DRM_INVALID_SIG", "message":"The required Windows Media Digital Rights Management (DRM) component cannot be validated. You might be able resolve the problem by reinstalling the Player."},

0xC00D11D8: { "code": "NS_E_WMP_DRM_CANNOT_RESTORE", "message":"You have exceeded your restore limit for the day. Try restoring your media usage rights tomorrow."},

0xC00D11D9: { "code": "NS_E_WMP_BURN_DISC_OVERFLOW", "message":"Some files might not fit on the CD. The required space cannot be calculated accurately because some files might be missing duration information. To ensure the calculation is accurate, play the files that are missing duration information."},

0xC00D11DA: { "code": "NS_E_WMP_DRM_GENERIC_LICENSE_FAILURE", "message":"Windows Media Player cannot verify the file's media usage rights. If you obtained this file from an online store, go to the online store to get the necessary rights."},

0xC00D11DB: { "code": "NS_E_WMP_DRM_NO_SECURE_CLOCK", "message":"It is not possible to sync because this device's internal clock is not set correctly. To set the clock, select the option to set the device clock on the Privacy tab of the Options dialog box, connect to the Internet, and then sync the device again. For additional assistance, click Web Help."},

0xC00D11DC: { "code": "NS_E_WMP_DRM_NO_RIGHTS", "message":"Windows Media Player cannot play, burn, rip, or sync the protected file because you do not have the appropriate rights."},

0xC00D11DD: { "code": "NS_E_WMP_DRM_INDIV_FAILED", "message":"Windows Media Player encountered an error during upgrade."},

0xC00D11DE: { "code": "NS_E_WMP_SERVER_NONEWCONNECTIONS", "message":"Windows Media Player cannot connect to the server because it is not accepting any new connections. This could be because it has reached its maximum connection limit. Please try again later."},

0xC00D11DF: { "code": "NS_E_WMP_MULTIPLE_ERROR_IN_PLAYLIST", "message":"A number of queued files cannot be played. To find information about the problem, click the Now Playing tab, and then click the icon next to each file in the List pane."},

0xC00D11E0: { "code": "NS_E_WMP_IMAPI2_ERASE_FAIL", "message":"Windows Media Player encountered an error while erasing the rewritable CD or DVD. Verify that the CD or DVD burner is connected properly and that the disc is clean and not damaged."},

0xC00D11E1: { "code": "NS_E_WMP_IMAPI2_ERASE_DEVICE_BUSY", "message":"Windows Media Player cannot erase the rewritable CD or DVD. Verify that the CD or DVD burner is connected properly and that the disc is clean and not damaged. If the burner is already in use, wait until the current task finishes or quit other programs that might be using the burner."},

0xC00D11E2: { "code": "NS_E_WMP_DRM_COMPONENT_FAILURE", "message":"A Windows Media Digital Rights Management (DRM) component encountered a problem. If you are trying to use a file that you obtained from an online store, try going to the online store and getting the appropriate usage rights."},

0xC00D11E3: { "code": "NS_E_WMP_DRM_NO_DEVICE_CERT", "message":"It is not possible to obtain device's certificate. Please contact the device manufacturer for a firmware update or for other steps to resolve this problem."},

0xC00D11E4: { "code": "NS_E_WMP_SERVER_SECURITY_ERROR", "message":"Windows Media Player encountered an error when connecting to the server. The security information from the server could not be validated."},

0xC00D11E5: { "code": "NS_E_WMP_AUDIO_DEVICE_LOST", "message":"An audio device was disconnected or reconfigured. Verify that the audio device is connected, and then try to play the item again."},

0xC00D11E6: { "code": "NS_E_WMP_IMAPI_MEDIA_INCOMPATIBLE", "message":"Windows Media Player could not complete burning because the disc is not compatible with your drive. Try inserting a different kind of recordable media or use a disc that supports a write speed that is compatible with your drive."},

0xC00D11EE: { "code": "NS_E_SYNCWIZ_DEVICE_FULL", "message":"Windows Media Player cannot save the sync settings because your device is full. Delete some unneeded files on your device and then try again."},

0xC00D11EF: { "code": "NS_E_SYNCWIZ_CANNOT_CHANGE_SETTINGS", "message":"It is not possible to change sync settings at this time. Try again later."},

0xC00D11F0: { "code": "NS_E_TRANSCODE_DELETECACHEERROR", "message":"Windows Media Player cannot delete these files currently. If the Player is synchronizing, wait until it is complete and then try again."},

0xC00D11F8: { "code": "NS_E_CD_NO_BUFFERS_READ", "message":"Windows Media Player could not use digital mode to read the CD. The Player has automatically switched the CD drive to analog mode. To switch back to digital mode, use the Devices tab. For additional assistance, click Web Help."},

0xC00D11F9: { "code": "NS_E_CD_EMPTY_TRACK_QUEUE", "message":"No CD track was specified for playback."},

0xC00D11FA: { "code": "NS_E_CD_NO_READER", "message":"The CD filter was not able to create the CD reader."},

0xC00D11FB: { "code": "NS_E_CD_ISRC_INVALID", "message":"Invalid ISRC code."},

0xC00D11FC: { "code": "NS_E_CD_MEDIA_CATALOG_NUMBER_INVALID", "message":"Invalid Media Catalog Number."},

0xC00D11FD: { "code": "NS_E_SLOW_READ_DIGITAL_WITH_ERRORCORRECTION", "message":"Windows Media Player cannot play audio CDs correctly because the CD drive is slow and error correction is turned on. To increase performance, turn off playback error correction for this drive."},

0xC00D11FE: { "code": "NS_E_CD_SPEEDDETECT_NOT_ENOUGH_READS", "message":"Windows Media Player cannot estimate the CD drive's playback speed because the CD track is too short."},

0xC00D11FF: { "code": "NS_E_CD_QUEUEING_DISABLED", "message":"Cannot queue the CD track because queuing is not enabled."},

0xC00D1202: { "code": "NS_E_WMP_DRM_ACQUIRING_LICENSE", "message":"Windows Media Player cannot download additional media usage rights until the current download is complete."},

0xC00D1203: { "code": "NS_E_WMP_DRM_LICENSE_EXPIRED", "message":"The media usage rights for this file have expired or are no longer valid. If you obtained the file from an online store, sign in to the store, and then try again."},

0xC00D1204: { "code": "NS_E_WMP_DRM_LICENSE_NOTACQUIRED", "message":"Windows Media Player cannot download the media usage rights for the file. If you obtained the file from an online store, sign in to the store, and then try again."},

0xC00D1205: { "code": "NS_E_WMP_DRM_LICENSE_NOTENABLED", "message":"The media usage rights for this file are not yet valid. To see when they will become valid, right-click the file in the library, click Properties, and then click the Media Usage Rights tab."},

0xC00D1206: { "code": "NS_E_WMP_DRM_LICENSE_UNUSABLE", "message":"The media usage rights for this file are not valid. If you obtained this file from an online store, contact the store for assistance."},

0xC00D1207: { "code": "NS_E_WMP_DRM_LICENSE_CONTENT_REVOKED", "message":"The content provider has revoked the media usage rights for this file. If you obtained this file from an online store, ask the store if a new version of the file is available."},

0xC00D1208: { "code": "NS_E_WMP_DRM_LICENSE_NOSAP", "message":"The media usage rights for this file require a feature that is not supported in your current version of Windows Media Player or your current version of Windows. Try installing the latest version of the Player. If you obtained this file from an online store, contact the store for further assistance."},

0xC00D1209: { "code": "NS_E_WMP_DRM_UNABLE_TO_ACQUIRE_LICENSE", "message":"Windows Media Player cannot download media usage rights at this time. Try again later."},

0xC00D120A: { "code": "NS_E_WMP_LICENSE_REQUIRED", "message":"Windows Media Player cannot play, burn, or sync the file because the media usage rights are missing. If you obtained the file from an online store, sign in to the store, and then try again."},

0xC00D120B: { "code": "NS_E_WMP_PROTECTED_CONTENT", "message":"Windows Media Player cannot play, burn, or sync the file because the media usage rights are missing. If you obtained the file from an online store, sign in to the store, and then try again."},

0xC00D122A: { "code": "NS_E_WMP_POLICY_VALUE_NOT_CONFIGURED", "message":"Windows Media Player cannot read a policy. This can occur when the policy does not exist in the registry or when the registry cannot be read."},

0xC00D1234: { "code": "NS_E_PDA_CANNOT_SYNC_FROM_INTERNET", "message":"Windows Media Player cannot sync content streamed directly from the Internet. If possible, download the file to your computer, and then try to sync the file."},

0xC00D1235: { "code": "NS_E_PDA_CANNOT_SYNC_INVALID_PLAYLIST", "message":"This playlist is not valid or is corrupted. Create a new playlist using Windows Media Player, then sync the new playlist instead."},

0xC00D1236: { "code": "NS_E_PDA_FAILED_TO_SYNCHRONIZE_FILE", "message":"Windows Media Player encountered a problem while synchronizing the file to the device. For additional assistance, click Web Help."},

0xC00D1237: { "code": "NS_E_PDA_SYNC_FAILED", "message":"Windows Media Player encountered an error while synchronizing to the device."},

0xC00D1238: { "code": "NS_E_PDA_DELETE_FAILED", "message":"Windows Media Player cannot delete a file from the device."},

0xC00D1239: { "code": "NS_E_PDA_FAILED_TO_RETRIEVE_FILE", "message":"Windows Media Player cannot copy a file from the device to your library."},

0xC00D123A: { "code": "NS_E_PDA_DEVICE_NOT_RESPONDING", "message":"Windows Media Player cannot communicate with the device because the device is not responding. Try reconnecting the device, resetting the device, or contacting the device manufacturer for updated firmware."},

0xC00D123B: { "code": "NS_E_PDA_FAILED_TO_TRANSCODE_PHOTO", "message":"Windows Media Player cannot sync the picture to the device because a problem occurred while converting the file to another quality level or format. The original file might be damaged or corrupted."},

0xC00D123C: { "code": "NS_E_PDA_FAILED_TO_ENCRYPT_TRANSCODED_FILE", "message":"Windows Media Player cannot convert the file. The file might have been encrypted by the Encrypted File System (EFS). Try decrypting the file first and then synchronizing it. For information about how to decrypt a file, see Windows Help and Support."},

0xC00D123D: { "code": "NS_E_PDA_CANNOT_TRANSCODE_TO_AUDIO", "message":"Your device requires that this file be converted in order to play on the device. However, the device either does not support playing audio, or Windows Media Player cannot convert the file to an audio format that is supported by the device."},

0xC00D123E: { "code": "NS_E_PDA_CANNOT_TRANSCODE_TO_VIDEO", "message":"Your device requires that this file be converted in order to play on the device. However, the device either does not support playing video, or Windows Media Player cannot convert the file to a video format that is supported by the device."},

0xC00D123F: { "code": "NS_E_PDA_CANNOT_TRANSCODE_TO_IMAGE", "message":"Your device requires that this file be converted in order to play on the device. However, the device either does not support displaying pictures, or Windows Media Player cannot convert the file to a picture format that is supported by the device."},

0xC00D1240: { "code": "NS_E_PDA_RETRIEVED_FILE_FILENAME_TOO_LONG", "message":"Windows Media Player cannot sync the file to your computer because the file name is too long. Try renaming the file on the device."},

0xC00D1241: { "code": "NS_E_PDA_CEWMDM_DRM_ERROR", "message":"Windows Media Player cannot sync the file because the device is not responding. This typically occurs when there is a problem with the device firmware. For additional assistance, click Web Help."},

0xC00D1242: { "code": "NS_E_INCOMPLETE_PLAYLIST", "message":"Incomplete playlist."},

0xC00D1243: { "code": "NS_E_PDA_SYNC_RUNNING", "message":"It is not possible to perform the requested action because sync is in progress. You can either stop sync or wait for it to complete, and then try again."},

0xC00D1244: { "code": "NS_E_PDA_SYNC_LOGIN_ERROR", "message":"Windows Media Player cannot sync the subscription content because you are not signed in to the online store that provided it. Sign in to the online store, and then try again."},

0xC00D1245: { "code": "NS_E_PDA_TRANSCODE_CODEC_NOT_FOUND", "message":"Windows Media Player cannot convert the file to the format required by the device. One or more codecs required to convert the file could not be found."},

0xC00D1246: { "code": "NS_E_CANNOT_SYNC_DRM_TO_NON_JANUS_DEVICE", "message":"It is not possible to sync subscription files to this device."},

0xC00D1247: { "code": "NS_E_CANNOT_SYNC_PREVIOUS_SYNC_RUNNING", "message":"Your device is operating slowly or is not responding. Until the device responds, it is not possible to sync again. To return the device to normal operation, try disconnecting it from the computer or resetting it."},

0xC00D125C: { "code": "NS_E_WMP_HWND_NOTFOUND", "message":"The Windows Media Player download manager cannot function properly because the Player main window cannot be found. Try restarting the Player."},

0xC00D125D: { "code": "NS_E_BKGDOWNLOAD_WRONG_NO_FILES", "message":"Windows Media Player encountered a download that has the wrong number of files. This might occur if another program is trying to create jobs with the same signature as the Player."},

0xC00D125E: { "code": "NS_E_BKGDOWNLOAD_COMPLETECANCELLEDJOB", "message":"Windows Media Player tried to complete a download that was already canceled. The file will not be available."},

0xC00D125F: { "code": "NS_E_BKGDOWNLOAD_CANCELCOMPLETEDJOB", "message":"Windows Media Player tried to cancel a download that was already completed. The file will not be removed."},

0xC00D1260: { "code": "NS_E_BKGDOWNLOAD_NOJOBPOINTER", "message":"Windows Media Player is trying to access a download that is not valid."},

0xC00D1261: { "code": "NS_E_BKGDOWNLOAD_INVALIDJOBSIGNATURE", "message":"This download was not created by Windows Media Player."},

0xC00D1262: { "code": "NS_E_BKGDOWNLOAD_FAILED_TO_CREATE_TEMPFILE", "message":"The Windows Media Player download manager cannot create a temporary file name. This might occur if the path is not valid or if the disk is full."},

0xC00D1263: { "code": "NS_E_BKGDOWNLOAD_PLUGIN_FAILEDINITIALIZE", "message":"The Windows Media Player download manager plug-in cannot start. This might occur if the system is out of resources."},

0xC00D1264: { "code": "NS_E_BKGDOWNLOAD_PLUGIN_FAILEDTOMOVEFILE", "message":"The Windows Media Player download manager cannot move the file."},

0xC00D1265: { "code": "NS_E_BKGDOWNLOAD_CALLFUNCFAILED", "message":"The Windows Media Player download manager cannot perform a task because the system has no resources to allocate."},

0xC00D1266: { "code": "NS_E_BKGDOWNLOAD_CALLFUNCTIMEOUT", "message":"The Windows Media Player download manager cannot perform a task because the task took too long to run."},

0xC00D1267: { "code": "NS_E_BKGDOWNLOAD_CALLFUNCENDED", "message":"The Windows Media Player download manager cannot perform a task because the Player is terminating the service. The task will be recovered when the Player restarts."},

0xC00D1268: { "code": "NS_E_BKGDOWNLOAD_WMDUNPACKFAILED", "message":"The Windows Media Player download manager cannot expand a WMD file. The file will be deleted and the operation will not be completed successfully."},

0xC00D1269: { "code": "NS_E_BKGDOWNLOAD_FAILEDINITIALIZE", "message":"The Windows Media Player download manager cannot start. This might occur if the system is out of resources."},

0xC00D126A: { "code": "NS_E_INTERFACE_NOT_REGISTERED_IN_GIT", "message":"Windows Media Player cannot access a required functionality. This might occur if the wrong system files or Player DLLs are loaded."},

0xC00D126B: { "code": "NS_E_BKGDOWNLOAD_INVALID_FILE_NAME", "message":"Windows Media Player cannot get the file name of the requested download. The requested download will be canceled."},

0xC00D128E: { "code": "NS_E_IMAGE_DOWNLOAD_FAILED", "message":"Windows Media Player encountered an error while downloading an image."},

0xC00D12C0: { "code": "NS_E_WMP_UDRM_NOUSERLIST", "message":"Windows Media Player cannot update your media usage rights because the Player cannot verify the list of activated users of this computer."},

0xC00D12C1: { "code": "NS_E_WMP_DRM_NOT_ACQUIRING", "message":"Windows Media Player is trying to acquire media usage rights for a file that is no longer being used. Rights acquisition will stop."},

0xC00D12F2: { "code": "NS_E_WMP_BSTR_TOO_LONG", "message":"The parameter is not valid."},

0xC00D12FC: { "code": "NS_E_WMP_AUTOPLAY_INVALID_STATE", "message":"The state is not valid for this request."},

0xC00D1306: { "code": "NS_E_WMP_COMPONENT_REVOKED", "message":"Windows Media Player cannot play this file until you complete the software component upgrade. After the component has been upgraded, try to play the file again."},

0xC00D1324: { "code": "NS_E_CURL_NOTSAFE", "message":"The URL is not safe for the operation specified."},

0xC00D1325: { "code": "NS_E_CURL_INVALIDCHAR", "message":"The URL contains one or more characters that are not valid."},

0xC00D1326: { "code": "NS_E_CURL_INVALIDHOSTNAME", "message":"The URL contains a host name that is not valid."},

0xC00D1327: { "code": "NS_E_CURL_INVALIDPATH", "message":"The URL contains a path that is not valid."},

0xC00D1328: { "code": "NS_E_CURL_INVALIDSCHEME", "message":"The URL contains a scheme that is not valid."},

0xC00D1329: { "code": "NS_E_CURL_INVALIDURL", "message":"The URL is not valid."},

0xC00D132B: { "code": "NS_E_CURL_CANTWALK", "message":"Windows Media Player cannot play the file. If you clicked a link on a web page, the link might not be valid."},

0xC00D132C: { "code": "NS_E_CURL_INVALIDPORT", "message":"The URL port is not valid."},

0xC00D132D: { "code": "NS_E_CURLHELPER_NOTADIRECTORY", "message":"The URL is not a directory."},

0xC00D132E: { "code": "NS_E_CURLHELPER_NOTAFILE", "message":"The URL is not a file."},

0xC00D132F: { "code": "NS_E_CURL_CANTDECODE", "message":"The URL contains characters that cannot be decoded. The URL might be truncated or incomplete."},

0xC00D1330: { "code": "NS_E_CURLHELPER_NOTRELATIVE", "message":"The specified URL is not a relative URL."},

0xC00D1331: { "code": "NS_E_CURL_INVALIDBUFFERSIZE", "message":"The buffer is smaller than the size specified."},

0xC00D1356: { "code": "NS_E_SUBSCRIPTIONSERVICE_PLAYBACK_DISALLOWED", "message":"The content provider has not granted you the right to play this file. Go to the content provider's online store to get play rights."},

0xC00D1357: { "code": "NS_E_CANNOT_BUY_OR_DOWNLOAD_FROM_MULTIPLE_SERVICES", "message":"Windows Media Player cannot purchase or download content from multiple online stores."},

0xC00D1358: { "code": "NS_E_CANNOT_BUY_OR_DOWNLOAD_CONTENT", "message":"The file cannot be purchased or downloaded. The file might not be available from the online store."},

0xC00D135A: { "code": "NS_E_NOT_CONTENT_PARTNER_TRACK", "message":"The provider of this file cannot be identified."},

0xC00D135B: { "code": "NS_E_TRACK_DOWNLOAD_REQUIRES_ALBUM_PURCHASE", "message":"The file is only available for download when you buy the entire album."},

0xC00D135C: { "code": "NS_E_TRACK_DOWNLOAD_REQUIRES_PURCHASE", "message":"You must buy the file before you can download it."},

0xC00D135D: { "code": "NS_E_TRACK_PURCHASE_MAXIMUM_EXCEEDED", "message":"You have exceeded the maximum number of files that can be purchased in a single transaction."},

0xC00D135F: { "code": "NS_E_SUBSCRIPTIONSERVICE_LOGIN_FAILED", "message":"Windows Media Player cannot sign in to the online store. Verify that you are using the correct user name and password. If the problem persists, the store might be temporarily unavailable."},

0xC00D1360: { "code": "NS_E_SUBSCRIPTIONSERVICE_DOWNLOAD_TIMEOUT", "message":"Windows Media Player cannot download this item because the server is not responding. The server might be temporarily unavailable or the Internet connection might be lost."},

0xC00D1362: { "code": "NS_E_CONTENT_PARTNER_STILL_INITIALIZING", "message":"Content Partner still initializing."},

0xC00D1363: { "code": "NS_E_OPEN_CONTAINING_FOLDER_FAILED", "message":"The folder could not be opened. The folder might have been moved or deleted."},

0xC00D136A: { "code": "NS_E_ADVANCEDEDIT_TOO_MANY_PICTURES", "message":"Windows Media Player could not add all of the images to the file because the images exceeded the 7 megabyte (MB) limit."},

0xC00D1388: { "code": "NS_E_REDIRECT", "message":"The client redirected to another server."},

0xC00D1389: { "code": "NS_E_STALE_PRESENTATION", "message":"The streaming media description is no longer current."},

0xC00D138A: { "code": "NS_E_NAMESPACE_WRONG_PERSIST", "message":"It is not possible to create a persistent namespace node under a transient parent node."},

0xC00D138B: { "code": "NS_E_NAMESPACE_WRONG_TYPE", "message":"It is not possible to store a value in a namespace node that has a different value type."},

0xC00D138C: { "code": "NS_E_NAMESPACE_NODE_CONFLICT", "message":"It is not possible to remove the root namespace node."},

0xC00D138D: { "code": "NS_E_NAMESPACE_NODE_NOT_FOUND", "message":"The specified namespace node could not be found."},

0xC00D138E: { "code": "NS_E_NAMESPACE_BUFFER_TOO_SMALL", "message":"The buffer supplied to hold namespace node string is too small."},

0xC00D138F: { "code": "NS_E_NAMESPACE_TOO_MANY_CALLBACKS", "message":"The callback list on a namespace node is at the maximum size."},

0xC00D1390: { "code": "NS_E_NAMESPACE_DUPLICATE_CALLBACK", "message":"It is not possible to register an already-registered callback on a namespace node."},

0xC00D1391: { "code": "NS_E_NAMESPACE_CALLBACK_NOT_FOUND", "message":"Cannot find the callback in the namespace when attempting to remove the callback."},

0xC00D1392: { "code": "NS_E_NAMESPACE_NAME_TOO_LONG", "message":"The namespace node name exceeds the allowed maximum length."},

0xC00D1393: { "code": "NS_E_NAMESPACE_DUPLICATE_NAME", "message":"Cannot create a namespace node that already exists."},

0xC00D1394: { "code": "NS_E_NAMESPACE_EMPTY_NAME", "message":"The namespace node name cannot be a null string."},

0xC00D1395: { "code": "NS_E_NAMESPACE_INDEX_TOO_LARGE", "message":"Finding a child namespace node by index failed because the index exceeded the number of children."},

0xC00D1396: { "code": "NS_E_NAMESPACE_BAD_NAME", "message":"The namespace node name is invalid."},

0xC00D1397: { "code": "NS_E_NAMESPACE_WRONG_SECURITY", "message":"It is not possible to store a value in a namespace node that has a different security type."},

0xC00D13EC: { "code": "NS_E_CACHE_ARCHIVE_CONFLICT", "message":"The archive request conflicts with other requests in progress."},

0xC00D13ED: { "code": "NS_E_CACHE_ORIGIN_SERVER_NOT_FOUND", "message":"The specified origin server cannot be found."},

0xC00D13EE: { "code": "NS_E_CACHE_ORIGIN_SERVER_TIMEOUT", "message":"The specified origin server is not responding."},

0xC00D13EF: { "code": "NS_E_CACHE_NOT_BROADCAST", "message":"The internal code for HTTP status code 412 Precondition Failed due to not broadcast type."},

0xC00D13F0: { "code": "NS_E_CACHE_CANNOT_BE_CACHED", "message":"The internal code for HTTP status code 403 Forbidden due to not cacheable."},

0xC00D13F1: { "code": "NS_E_CACHE_NOT_MODIFIED", "message":"The internal code for HTTP status code 304 Not Modified."},

0xC00D1450: { "code": "NS_E_CANNOT_REMOVE_PUBLISHING_POINT", "message":"It is not possible to remove a cache or proxy publishing point."},

0xC00D1451: { "code": "NS_E_CANNOT_REMOVE_PLUGIN", "message":"It is not possible to remove the last instance of a type of plug-in."},

0xC00D1452: { "code": "NS_E_WRONG_PUBLISHING_POINT_TYPE", "message":"Cache and proxy publishing points do not support this property or method."},

0xC00D1453: { "code": "NS_E_UNSUPPORTED_LOAD_TYPE", "message":"The plug-in does not support the specified load type."},

0xC00D1454: { "code": "NS_E_INVALID_PLUGIN_LOAD_TYPE_CONFIGURATION", "message":"The plug-in does not support any load types. The plug-in must support at least one load type."},

0xC00D1455: { "code": "NS_E_INVALID_PUBLISHING_POINT_NAME", "message":"The publishing point name is invalid."},

0xC00D1456: { "code": "NS_E_TOO_MANY_MULTICAST_SINKS", "message":"Only one multicast data writer plug-in can be enabled for a publishing point."},

0xC00D1457: { "code": "NS_E_PUBLISHING_POINT_INVALID_REQUEST_WHILE_STARTED", "message":"The requested operation cannot be completed while the publishing point is started."},

0xC00D1458: { "code": "NS_E_MULTICAST_PLUGIN_NOT_ENABLED", "message":"A multicast data writer plug-in must be enabled in order for this operation to be completed."},

0xC00D1459: { "code": "NS_E_INVALID_OPERATING_SYSTEM_VERSION", "message":"This feature requires Windows Server 2003, Enterprise Edition."},

0xC00D145A: { "code": "NS_E_PUBLISHING_POINT_REMOVED", "message":"The requested operation cannot be completed because the specified publishing point has been removed."},

0xC00D145B: { "code": "NS_E_INVALID_PUSH_PUBLISHING_POINT_START_REQUEST", "message":"Push publishing points are started when the encoder starts pushing the stream. This publishing point cannot be started by the server administrator."},

0xC00D145C: { "code": "NS_E_UNSUPPORTED_LANGUAGE", "message":"The specified language is not supported."},

0xC00D145D: { "code": "NS_E_WRONG_OS_VERSION", "message":"Windows Media Services will only run on Windows Server 2003, Standard Edition and Windows Server 2003, Enterprise Edition."},

0xC00D145E: { "code": "NS_E_PUBLISHING_POINT_STOPPED", "message":"The operation cannot be completed because the publishing point has been stopped."},

0xC00D14B4: { "code": "NS_E_PLAYLIST_ENTRY_ALREADY_PLAYING", "message":"The playlist entry is already playing."},

0xC00D14B5: { "code": "NS_E_EMPTY_PLAYLIST", "message":"The playlist or directory you are requesting does not contain content."},

0xC00D14B6: { "code": "NS_E_PLAYLIST_PARSE_FAILURE", "message":"The server was unable to parse the requested playlist file."},

0xC00D14B7: { "code": "NS_E_PLAYLIST_UNSUPPORTED_ENTRY", "message":"The requested operation is not supported for this type of playlist entry."},

0xC00D14B8: { "code": "NS_E_PLAYLIST_ENTRY_NOT_IN_PLAYLIST", "message":"Cannot jump to a playlist entry that is not inserted in the playlist."},

0xC00D14B9: { "code": "NS_E_PLAYLIST_ENTRY_SEEK", "message":"Cannot seek to the desired playlist entry."},

0xC00D14BA: { "code": "NS_E_PLAYLIST_RECURSIVE_PLAYLISTS", "message":"Cannot play recursive playlist."},

0xC00D14BB: { "code": "NS_E_PLAYLIST_TOO_MANY_NESTED_PLAYLISTS", "message":"The number of nested playlists exceeded the limit the server can handle."},

0xC00D14BC: { "code": "NS_E_PLAYLIST_SHUTDOWN", "message":"Cannot execute the requested operation because the playlist has been shut down by the Media Server."},

0xC00D14BD: { "code": "NS_E_PLAYLIST_END_RECEDING", "message":"The playlist has ended while receding."},

0xC00D1518: { "code": "NS_E_DATAPATH_NO_SINK", "message":"The data path does not have an associated data writer plug-in."},

0xC00D151A: { "code": "NS_E_INVALID_PUSH_TEMPLATE", "message":"The specified push template is invalid."},

0xC00D151B: { "code": "NS_E_INVALID_PUSH_PUBLISHING_POINT", "message":"The specified push publishing point is invalid."},

0xC00D151C: { "code": "NS_E_CRITICAL_ERROR", "message":"The requested operation cannot be performed because the server or publishing point is in a critical error state."},

0xC00D151D: { "code": "NS_E_NO_NEW_CONNECTIONS", "message":"The content cannot be played because the server is not currently accepting connections. Try connecting at a later time."},

0xC00D151E: { "code": "NS_E_WSX_INVALID_VERSION", "message":"The version of this playlist is not supported by the server."},

0xC00D151F: { "code": "NS_E_HEADER_MISMATCH", "message":"The command does not apply to the current media header user by a server component."},

0xC00D1520: { "code": "NS_E_PUSH_DUPLICATE_PUBLISHING_POINT_NAME", "message":"The specified publishing point name is already in use."},

0xC00D157C: { "code": "NS_E_NO_SCRIPT_ENGINE", "message":"There is no script engine available for this file."},

0xC00D157D: { "code": "NS_E_PLUGIN_ERROR_REPORTED", "message":"The plug-in has reported an error. See the Troubleshooting tab or the NT Application Event Log for details."},

0xC00D157E: { "code": "NS_E_SOURCE_PLUGIN_NOT_FOUND", "message":"No enabled data source plug-in is available to access the requested content."},

0xC00D157F: { "code": "NS_E_PLAYLIST_PLUGIN_NOT_FOUND", "message":"No enabled playlist parser plug-in is available to access the requested content."},

0xC00D1580: { "code": "NS_E_DATA_SOURCE_ENUMERATION_NOT_SUPPORTED", "message":"The data source plug-in does not support enumeration."},

0xC00D1581: { "code": "NS_E_MEDIA_PARSER_INVALID_FORMAT", "message":"The server cannot stream the selected file because it is either damaged or corrupt. Select a different file."},

0xC00D1582: { "code": "NS_E_SCRIPT_DEBUGGER_NOT_INSTALLED", "message":"The plug-in cannot be enabled because a compatible script debugger is not installed on this system. Install a script debugger, or disable the script debugger option on the general tab of the plug-in's properties page and try again."},

0xC00D1583: { "code": "NS_E_FEATURE_REQUIRES_ENTERPRISE_SERVER", "message":"The plug-in cannot be loaded because it requires Windows Server 2003, Enterprise Edition."},

0xC00D1584: { "code": "NS_E_WIZARD_RUNNING", "message":"Another wizard is currently running. Please close the other wizard or wait until it finishes before attempting to run this wizard again."},

0xC00D1585: { "code": "NS_E_INVALID_LOG_URL", "message":"Invalid log URL. Multicast logging URL must look like \"http://servername/isapibackend.dll\"."},

0xC00D1586: { "code": "NS_E_INVALID_MTU_RANGE", "message":"Invalid MTU specified. The valid range for maximum packet size is between 36 and 65507 bytes."},

0xC00D1587: { "code": "NS_E_INVALID_PLAY_STATISTICS", "message":"Invalid play statistics for logging."},

0xC00D1588: { "code": "NS_E_LOG_NEED_TO_BE_SKIPPED", "message":"The log needs to be skipped."},

0xC00D1589: { "code": "NS_E_HTTP_TEXT_DATACONTAINER_SIZE_LIMIT_EXCEEDED", "message":"The size of the data exceeded the limit the WMS HTTP Download Data Source plugin can handle."},

0xC00D158A: { "code": "NS_E_PORT_IN_USE", "message":"One usage of each socket address (protocol/network address/port) is permitted. Verify that other services or applications are not attempting to use the same port and then try to enable the plug-in again."},

0xC00D158B: { "code": "NS_E_PORT_IN_USE_HTTP", "message":"One usage of each socket address (protocol/network address/port) is permitted. Verify that other services (such as IIS) or applications are not attempting to use the same port and then try to enable the plug-in again."},

0xC00D158C: { "code": "NS_E_HTTP_TEXT_DATACONTAINER_INVALID_SERVER_RESPONSE", "message":"The WMS HTTP Download Data Source plugin was unable to receive the remote server's response."},

0xC00D158D: { "code": "NS_E_ARCHIVE_REACH_QUOTA", "message":"The archive plug-in has reached its quota."},

0xC00D158E: { "code": "NS_E_ARCHIVE_ABORT_DUE_TO_BCAST", "message":"The archive plug-in aborted because the source was from broadcast."},

0xC00D158F: { "code": "NS_E_ARCHIVE_GAP_DETECTED", "message":"The archive plug-in detected an interrupt in the source."},

0xC00D1590: { "code": "NS_E_AUTHORIZATION_FILE_NOT_FOUND", "message":"The system cannot find the file specified."},

0xC00D1B58: { "code": "NS_E_BAD_MARKIN", "message":"The mark-in time should be greater than 0 and less than the mark-out time."},

0xC00D1B59: { "code": "NS_E_BAD_MARKOUT", "message":"The mark-out time should be greater than the mark-in time and less than the file duration."},

0xC00D1B5A: { "code": "NS_E_NOMATCHING_MEDIASOURCE", "message":"No matching media type is found in the source %1."},

0xC00D1B5B: { "code": "NS_E_UNSUPPORTED_SOURCETYPE", "message":"The specified source type is not supported."},

0xC00D1B5C: { "code": "NS_E_TOO_MANY_AUDIO", "message":"It is not possible to specify more than one audio input."},

0xC00D1B5D: { "code": "NS_E_TOO_MANY_VIDEO", "message":"It is not possible to specify more than two video inputs."},

0xC00D1B5E: { "code": "NS_E_NOMATCHING_ELEMENT", "message":"No matching element is found in the list."},

0xC00D1B5F: { "code": "NS_E_MISMATCHED_MEDIACONTENT", "message":"The profile's media types must match the media types defined for the session."},

0xC00D1B60: { "code": "NS_E_CANNOT_DELETE_ACTIVE_SOURCEGROUP", "message":"It is not possible to remove an active source while encoding."},

0xC00D1B61: { "code": "NS_E_AUDIODEVICE_BUSY", "message":"It is not possible to open the specified audio capture device because it is currently in use."},

0xC00D1B62: { "code": "NS_E_AUDIODEVICE_UNEXPECTED", "message":"It is not possible to open the specified audio capture device because an unexpected error has occurred."},

0xC00D1B63: { "code": "NS_E_AUDIODEVICE_BADFORMAT", "message":"The audio capture device does not support the specified audio format."},

0xC00D1B64: { "code": "NS_E_VIDEODEVICE_BUSY", "message":"It is not possible to open the specified video capture device because it is currently in use."},

0xC00D1B65: { "code": "NS_E_VIDEODEVICE_UNEXPECTED", "message":"It is not possible to open the specified video capture device because an unexpected error has occurred."},

0xC00D1B66: { "code": "NS_E_INVALIDCALL_WHILE_ENCODER_RUNNING", "message":"This operation is not allowed while encoding."},

0xC00D1B67: { "code": "NS_E_NO_PROFILE_IN_SOURCEGROUP", "message":"No profile is set for the source."},

0xC00D1B68: { "code": "NS_E_VIDEODRIVER_UNSTABLE", "message":"The video capture driver returned an unrecoverable error. It is now in an unstable state."},

0xC00D1B69: { "code": "NS_E_VIDCAPSTARTFAILED", "message":"It was not possible to start the video device."},

0xC00D1B6A: { "code": "NS_E_VIDSOURCECOMPRESSION", "message":"The video source does not support the requested output format or color depth."},

0xC00D1B6B: { "code": "NS_E_VIDSOURCESIZE", "message":"The video source does not support the requested capture size."},

0xC00D1B6C: { "code": "NS_E_ICMQUERYFORMAT", "message":"It was not possible to obtain output information from the video compressor."},

0xC00D1B6D: { "code": "NS_E_VIDCAPCREATEWINDOW", "message":"It was not possible to create a video capture window."},

0xC00D1B6E: { "code": "NS_E_VIDCAPDRVINUSE", "message":"There is already a stream active on this video device."},

0xC00D1B6F: { "code": "NS_E_NO_MEDIAFORMAT_IN_SOURCE", "message":"No media format is set in source."},

0xC00D1B70: { "code": "NS_E_NO_VALID_OUTPUT_STREAM", "message":"Cannot find a valid output stream from the source."},

0xC00D1B71: { "code": "NS_E_NO_VALID_SOURCE_PLUGIN", "message":"It was not possible to find a valid source plug-in for the specified source."},

0xC00D1B72: { "code": "NS_E_NO_ACTIVE_SOURCEGROUP", "message":"No source is currently active."},

0xC00D1B73: { "code": "NS_E_NO_SCRIPT_STREAM", "message":"No script stream is set in the current source."},

0xC00D1B74: { "code": "NS_E_INVALIDCALL_WHILE_ARCHIVAL_RUNNING", "message":"This operation is not allowed while archiving."},

0xC00D1B75: { "code": "NS_E_INVALIDPACKETSIZE", "message":"The setting for the maximum packet size is not valid."},

0xC00D1B76: { "code": "NS_E_PLUGIN_CLSID_INVALID", "message":"The plug-in CLSID specified is not valid."},

0xC00D1B77: { "code": "NS_E_UNSUPPORTED_ARCHIVETYPE", "message":"This archive type is not supported."},

0xC00D1B78: { "code": "NS_E_UNSUPPORTED_ARCHIVEOPERATION", "message":"This archive operation is not supported."},

0xC00D1B79: { "code": "NS_E_ARCHIVE_FILENAME_NOTSET", "message":"The local archive file name was not set."},

0xC00D1B7A: { "code": "NS_E_SOURCEGROUP_NOTPREPARED", "message":"The source is not yet prepared."},

0xC00D1B7B: { "code": "NS_E_PROFILE_MISMATCH", "message":"Profiles on the sources do not match."},

0xC00D1B7C: { "code": "NS_E_INCORRECTCLIPSETTINGS", "message":"The specified crop values are not valid."},

0xC00D1B7D: { "code": "NS_E_NOSTATSAVAILABLE", "message":"No statistics are available at this time."},

0xC00D1B7E: { "code": "NS_E_NOTARCHIVING", "message":"The encoder is not archiving."},

0xC00D1B7F: { "code": "NS_E_INVALIDCALL_WHILE_ENCODER_STOPPED", "message":"This operation is only allowed during encoding."},

0xC00D1B80: { "code": "NS_E_NOSOURCEGROUPS", "message":"This SourceGroupCollection doesn't contain any SourceGroups."},

0xC00D1B81: { "code": "NS_E_INVALIDINPUTFPS", "message":"This source does not have a frame rate of 30 fps. Therefore, it is not possible to apply the inverse telecine filter to the source."},

0xC00D1B82: { "code": "NS_E_NO_DATAVIEW_SUPPORT", "message":"It is not possible to display your source or output video in the Video panel."},

0xC00D1B83: { "code": "NS_E_CODEC_UNAVAILABLE", "message":"One or more codecs required to open this content could not be found."},

0xC00D1B84: { "code": "NS_E_ARCHIVE_SAME_AS_INPUT", "message":"The archive file has the same name as an input file. Change one of the names before continuing."},

0xC00D1B85: { "code": "NS_E_SOURCE_NOTSPECIFIED", "message":"The source has not been set up completely."},

0xC00D1B86: { "code": "NS_E_NO_REALTIME_TIMECOMPRESSION", "message":"It is not possible to apply time compression to a broadcast session."},

0xC00D1B87: { "code": "NS_E_UNSUPPORTED_ENCODER_DEVICE", "message":"It is not possible to open this device."},

0xC00D1B88: { "code": "NS_E_UNEXPECTED_DISPLAY_SETTINGS", "message":"It is not possible to start encoding because the display size or color has changed since the current session was defined. Restore the previous settings or create a new session."},

0xC00D1B89: { "code": "NS_E_NO_AUDIODATA", "message":"No audio data has been received for several seconds. Check the audio source and restart the encoder."},

0xC00D1B8A: { "code": "NS_E_INPUTSOURCE_PROBLEM", "message":"One or all of the specified sources are not working properly. Check that the sources are configured correctly."},

0xC00D1B8B: { "code": "NS_E_WME_VERSION_MISMATCH", "message":"The supplied configuration file is not supported by this version of the encoder."},

0xC00D1B8C: { "code": "NS_E_NO_REALTIME_PREPROCESS", "message":"It is not possible to use image preprocessing with live encoding."},

0xC00D1B8D: { "code": "NS_E_NO_REPEAT_PREPROCESS", "message":"It is not possible to use two-pass encoding when the source is set to loop."},

0xC00D1B8E: { "code": "NS_E_CANNOT_PAUSE_LIVEBROADCAST", "message":"It is not possible to pause encoding during a broadcast."},

0xC00D1B8F: { "code": "NS_E_DRM_PROFILE_NOT_SET", "message":"A DRM profile has not been set for the current session."},

0xC00D1B90: { "code": "NS_E_DUPLICATE_DRMPROFILE", "message":"The profile ID is already used by a DRM profile. Specify a different profile ID."},

0xC00D1B91: { "code": "NS_E_INVALID_DEVICE", "message":"The setting of the selected device does not support control for playing back tapes."},

0xC00D1B92: { "code": "NS_E_SPEECHEDL_ON_NON_MIXEDMODE", "message":"You must specify a mixed voice and audio mode in order to use an optimization definition file."},

0xC00D1B93: { "code": "NS_E_DRM_PASSWORD_TOO_LONG", "message":"The specified password is too long. Type a password with fewer than 8 characters."},

0xC00D1B94: { "code": "NS_E_DEVCONTROL_FAILED_SEEK", "message":"It is not possible to seek to the specified mark-in point."},

0xC00D1B95: { "code": "NS_E_INTERLACE_REQUIRE_SAMESIZE", "message":"When you choose to maintain the interlacing in your video, the output video size must match the input video size."},

0xC00D1B96: { "code": "NS_E_TOO_MANY_DEVICECONTROL", "message":"Only one device control plug-in can control a device."},

0xC00D1B97: { "code": "NS_E_NO_MULTIPASS_FOR_LIVEDEVICE", "message":"You must also enable storing content to hard disk temporarily in order to use two-pass encoding with the input device."},

0xC00D1B98: { "code": "NS_E_MISSING_AUDIENCE", "message":"An audience is missing from the output stream configuration."},

0xC00D1B99: { "code": "NS_E_AUDIENCE_CONTENTTYPE_MISMATCH", "message":"All audiences in the output tree must have the same content type."},

0xC00D1B9A: { "code": "NS_E_MISSING_SOURCE_INDEX", "message":"A source index is missing from the output stream configuration."},

0xC00D1B9B: { "code": "NS_E_NUM_LANGUAGE_MISMATCH", "message":"The same source index in different audiences should have the same number of languages."},

0xC00D1B9C: { "code": "NS_E_LANGUAGE_MISMATCH", "message":"The same source index in different audiences should have the same languages."},

0xC00D1B9D: { "code": "NS_E_VBRMODE_MISMATCH", "message":"The same source index in different audiences should use the same VBR encoding mode."},

0xC00D1B9E: { "code": "NS_E_INVALID_INPUT_AUDIENCE_INDEX", "message":"The bit rate index specified is not valid."},

0xC00D1B9F: { "code": "NS_E_INVALID_INPUT_LANGUAGE", "message":"The specified language is not valid."},

0xC00D1BA0: { "code": "NS_E_INVALID_INPUT_STREAM", "message":"The specified source type is not valid."},

0xC00D1BA1: { "code": "NS_E_EXPECT_MONO_WAV_INPUT", "message":"The source must be a mono channel .wav file."},

0xC00D1BA2: { "code": "NS_E_INPUT_WAVFORMAT_MISMATCH", "message":"All the source .wav files must have the same format."},

0xC00D1BA3: { "code": "NS_E_RECORDQ_DISK_FULL", "message":"The hard disk being used for temporary storage of content has reached the minimum allowed disk space. Create more space on the hard disk and restart encoding."},

0xC00D1BA4: { "code": "NS_E_NO_PAL_INVERSE_TELECINE", "message":"It is not possible to apply the inverse telecine feature to PAL content."},

0xC00D1BA5: { "code": "NS_E_ACTIVE_SG_DEVICE_DISCONNECTED", "message":"A capture device in the current active source is no longer available."},

0xC00D1BA6: { "code": "NS_E_ACTIVE_SG_DEVICE_CONTROL_DISCONNECTED", "message":"A device used in the current active source for device control is no longer available."},

0xC00D1BA7: { "code": "NS_E_NO_FRAMES_SUBMITTED_TO_ANALYZER", "message":"No frames have been submitted to the analyzer for analysis."},

0xC00D1BA8: { "code": "NS_E_INPUT_DOESNOT_SUPPORT_SMPTE", "message":"The source video does not support time codes."},

0xC00D1BA9: { "code": "NS_E_NO_SMPTE_WITH_MULTIPLE_SOURCEGROUPS", "message":"It is not possible to generate a time code when there are multiple sources in a session."},

0xC00D1BAA: { "code": "NS_E_BAD_CONTENTEDL", "message":"The voice codec optimization definition file cannot be found or is corrupted."},

0xC00D1BAB: { "code": "NS_E_INTERLACEMODE_MISMATCH", "message":"The same source index in different audiences should have the same interlace mode."},

0xC00D1BAC: { "code": "NS_E_NONSQUAREPIXELMODE_MISMATCH", "message":"The same source index in different audiences should have the same nonsquare pixel mode."},

0xC00D1BAD: { "code": "NS_E_SMPTEMODE_MISMATCH", "message":"The same source index in different audiences should have the same time code mode."},

0xC00D1BAE: { "code": "NS_E_END_OF_TAPE", "message":"Either the end of the tape has been reached or there is no tape. Check the device and tape."},

0xC00D1BAF: { "code": "NS_E_NO_MEDIA_IN_AUDIENCE", "message":"No audio or video input has been specified."},

0xC00D1BB0: { "code": "NS_E_NO_AUDIENCES", "message":"The profile must contain a bit rate."},

0xC00D1BB1: { "code": "NS_E_NO_AUDIO_COMPAT", "message":"You must specify at least one audio stream to be compatible with Windows Media Player 7.1."},

0xC00D1BB2: { "code": "NS_E_INVALID_VBR_COMPAT", "message":"Using a VBR encoding mode is not compatible with Windows Media Player 7.1."},

0xC00D1BB3: { "code": "NS_E_NO_PROFILE_NAME", "message":"You must specify a profile name."},

0xC00D1BB4: { "code": "NS_E_INVALID_VBR_WITH_UNCOMP", "message":"It is not possible to use a VBR encoding mode with uncompressed audio or video."},

0xC00D1BB5: { "code": "NS_E_MULTIPLE_VBR_AUDIENCES", "message":"It is not possible to use MBR encoding with VBR encoding."},

0xC00D1BB6: { "code": "NS_E_UNCOMP_COMP_COMBINATION", "message":"It is not possible to mix uncompressed and compressed content in a session."},

0xC00D1BB7: { "code": "NS_E_MULTIPLE_AUDIO_CODECS", "message":"All audiences must use the same audio codec."},

0xC00D1BB8: { "code": "NS_E_MULTIPLE_AUDIO_FORMATS", "message":"All audiences should use the same audio format to be compatible with Windows Media Player 7.1."},

0xC00D1BB9: { "code": "NS_E_AUDIO_BITRATE_STEPDOWN", "message":"The audio bit rate for an audience with a higher total bit rate must be greater than one with a lower total bit rate."},

0xC00D1BBA: { "code": "NS_E_INVALID_AUDIO_PEAKRATE", "message":"The audio peak bit rate setting is not valid."},

0xC00D1BBB: { "code": "NS_E_INVALID_AUDIO_PEAKRATE_2", "message":"The audio peak bit rate setting must be greater than the audio bit rate setting."},

0xC00D1BBC: { "code": "NS_E_INVALID_AUDIO_BUFFERMAX", "message":"The setting for the maximum buffer size for audio is not valid."},

0xC00D1BBD: { "code": "NS_E_MULTIPLE_VIDEO_CODECS", "message":"All audiences must use the same video codec."},

0xC00D1BBE: { "code": "NS_E_MULTIPLE_VIDEO_SIZES", "message":"All audiences should use the same video size to be compatible with Windows Media Player 7.1."},

0xC00D1BBF: { "code": "NS_E_INVALID_VIDEO_BITRATE", "message":"The video bit rate setting is not valid."},

0xC00D1BC0: { "code": "NS_E_VIDEO_BITRATE_STEPDOWN", "message":"The video bit rate for an audience with a higher total bit rate must be greater than one with a lower total bit rate."},

0xC00D1BC1: { "code": "NS_E_INVALID_VIDEO_PEAKRATE", "message":"The video peak bit rate setting is not valid."},

0xC00D1BC2: { "code": "NS_E_INVALID_VIDEO_PEAKRATE_2", "message":"The video peak bit rate setting must be greater than the video bit rate setting."},

0xC00D1BC3: { "code": "NS_E_INVALID_VIDEO_WIDTH", "message":"The video width setting is not valid."},

0xC00D1BC4: { "code": "NS_E_INVALID_VIDEO_HEIGHT", "message":"The video height setting is not valid."},

0xC00D1BC5: { "code": "NS_E_INVALID_VIDEO_FPS", "message":"The video frame rate setting is not valid."},

0xC00D1BC6: { "code": "NS_E_INVALID_VIDEO_KEYFRAME", "message":"The video key frame setting is not valid."},

0xC00D1BC7: { "code": "NS_E_INVALID_VIDEO_IQUALITY", "message":"The video image quality setting is not valid."},

0xC00D1BC8: { "code": "NS_E_INVALID_VIDEO_CQUALITY", "message":"The video codec quality setting is not valid."},

0xC00D1BC9: { "code": "NS_E_INVALID_VIDEO_BUFFER", "message":"The video buffer setting is not valid."},

0xC00D1BCA: { "code": "NS_E_INVALID_VIDEO_BUFFERMAX", "message":"The setting for the maximum buffer size for video is not valid."},

0xC00D1BCB: { "code": "NS_E_INVALID_VIDEO_BUFFERMAX_2", "message":"The value of the video maximum buffer size setting must be greater than the video buffer size setting."},

0xC00D1BCC: { "code": "NS_E_INVALID_VIDEO_WIDTH_ALIGN", "message":"The alignment of the video width is not valid."},

0xC00D1BCD: { "code": "NS_E_INVALID_VIDEO_HEIGHT_ALIGN", "message":"The alignment of the video height is not valid."},

0xC00D1BCE: { "code": "NS_E_MULTIPLE_SCRIPT_BITRATES", "message":"All bit rates must have the same script bit rate."},

0xC00D1BCF: { "code": "NS_E_INVALID_SCRIPT_BITRATE", "message":"The script bit rate specified is not valid."},

0xC00D1BD0: { "code": "NS_E_MULTIPLE_FILE_BITRATES", "message":"All bit rates must have the same file transfer bit rate."},

0xC00D1BD1: { "code": "NS_E_INVALID_FILE_BITRATE", "message":"The file transfer bit rate is not valid."},

0xC00D1BD2: { "code": "NS_E_SAME_AS_INPUT_COMBINATION", "message":"All audiences in a profile should either be same as input or have video width and height specified."},

0xC00D1BD3: { "code": "NS_E_SOURCE_CANNOT_LOOP", "message":"This source type does not support looping."},

0xC00D1BD4: { "code": "NS_E_INVALID_FOLDDOWN_COEFFICIENTS", "message":"The fold-down value needs to be between -144 and 0."},

0xC00D1BD5: { "code": "NS_E_DRMPROFILE_NOTFOUND", "message":"The specified DRM profile does not exist in the system."},

0xC00D1BD6: { "code": "NS_E_INVALID_TIMECODE", "message":"The specified time code is not valid."},

0xC00D1BD7: { "code": "NS_E_NO_AUDIO_TIMECOMPRESSION", "message":"It is not possible to apply time compression to a video-only session."},

0xC00D1BD8: { "code": "NS_E_NO_TWOPASS_TIMECOMPRESSION", "message":"It is not possible to apply time compression to a session that is using two-pass encoding."},

0xC00D1BD9: { "code": "NS_E_TIMECODE_REQUIRES_VIDEOSTREAM", "message":"It is not possible to generate a time code for an audio-only session."},

0xC00D1BDA: { "code": "NS_E_NO_MBR_WITH_TIMECODE", "message":"It is not possible to generate a time code when you are encoding content at multiple bit rates."},

0xC00D1BDB: { "code": "NS_E_INVALID_INTERLACEMODE", "message":"The video codec selected does not support maintaining interlacing in video."},

0xC00D1BDC: { "code": "NS_E_INVALID_INTERLACE_COMPAT", "message":"Maintaining interlacing in video is not compatible with Windows Media Player 7.1."},

0xC00D1BDD: { "code": "NS_E_INVALID_NONSQUAREPIXEL_COMPAT", "message":"Allowing nonsquare pixel output is not compatible with Windows Media Player 7.1."},

0xC00D1BDE: { "code": "NS_E_INVALID_SOURCE_WITH_DEVICE_CONTROL", "message":"Only capture devices can be used with device control."},

0xC00D1BDF: { "code": "NS_E_CANNOT_GENERATE_BROADCAST_INFO_FOR_QUALITYVBR", "message":"It is not possible to generate the stream format file if you are using quality-based VBR encoding for the audio or video stream. Instead use the Windows Media file generated after encoding to create the announcement file."},

0xC00D1BE0: { "code": "NS_E_EXCEED_MAX_DRM_PROFILE_LIMIT", "message":"It is not possible to create a DRM profile because the maximum number of profiles has been reached. You must delete some DRM profiles before creating new ones."},

0xC00D1BE1: { "code": "NS_E_DEVICECONTROL_UNSTABLE", "message":"The device is in an unstable state. Check that the device is functioning properly and a tape is in place."},

0xC00D1BE2: { "code": "NS_E_INVALID_PIXEL_ASPECT_RATIO", "message":"The pixel aspect ratio value must be between 1 and 255."},

0xC00D1BE3: { "code": "NS_E_AUDIENCE__LANGUAGE_CONTENTTYPE_MISMATCH", "message":"All streams with different languages in the same audience must have same properties."},

0xC00D1BE4: { "code": "NS_E_INVALID_PROFILE_CONTENTTYPE", "message":"The profile must contain at least one audio or video stream."},

0xC00D1BE5: { "code": "NS_E_TRANSFORM_PLUGIN_NOT_FOUND", "message":"The transform plug-in could not be found."},

0xC00D1BE6: { "code": "NS_E_TRANSFORM_PLUGIN_INVALID", "message":"The transform plug-in is not valid. It might be damaged or you might not have the required permissions to access the plug-in."},

0xC00D1BE7: { "code": "NS_E_EDL_REQUIRED_FOR_DEVICE_MULTIPASS", "message":"To use two-pass encoding, you must enable device control and setup an edit decision list (EDL) that has at least one entry."},

0xC00D1BE8: { "code": "NS_E_INVALID_VIDEO_WIDTH_FOR_INTERLACED_ENCODING", "message":"When you choose to maintain the interlacing in your video, the output video size must be a multiple of 4."},

0xC00D1BE9: { "code": "NS_E_MARKIN_UNSUPPORTED", "message":"Markin/Markout is unsupported with this source type."},

0xC00D2711: { "code": "NS_E_DRM_INVALID_APPLICATION", "message":"A problem has occurred in the Digital Rights Management component. Contact product support for this application."},

0xC00D2712: { "code": "NS_E_DRM_LICENSE_STORE_ERROR", "message":"License storage is not working. Contact Microsoft product support."},

0xC00D2713: { "code": "NS_E_DRM_SECURE_STORE_ERROR", "message":"Secure storage is not working. Contact Microsoft product support."},

0xC00D2714: { "code": "NS_E_DRM_LICENSE_STORE_SAVE_ERROR", "message":"License acquisition did not work. Acquire a new license or contact the content provider for further assistance."},

0xC00D2715: { "code": "NS_E_DRM_SECURE_STORE_UNLOCK_ERROR", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2716: { "code": "NS_E_DRM_INVALID_CONTENT", "message":"The media file is corrupted. Contact the content provider to get a new file."},

0xC00D2717: { "code": "NS_E_DRM_UNABLE_TO_OPEN_LICENSE", "message":"The license is corrupted. Acquire a new license."},

0xC00D2718: { "code": "NS_E_DRM_INVALID_LICENSE", "message":"The license is corrupted or invalid. Acquire a new license"},

0xC00D2719: { "code": "NS_E_DRM_INVALID_MACHINE", "message":"Licenses cannot be copied from one computer to another. Use License Management to transfer licenses, or get a new license for the media file."},

0xC00D271B: { "code": "NS_E_DRM_ENUM_LICENSE_FAILED", "message":"License storage is not working. Contact Microsoft product support."},

0xC00D271C: { "code": "NS_E_DRM_INVALID_LICENSE_REQUEST", "message":"The media file is corrupted. Contact the content provider to get a new file."},

0xC00D271D: { "code": "NS_E_DRM_UNABLE_TO_INITIALIZE", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D271E: { "code": "NS_E_DRM_UNABLE_TO_ACQUIRE_LICENSE", "message":"The license could not be acquired. Try again later."},

0xC00D271F: { "code": "NS_E_DRM_INVALID_LICENSE_ACQUIRED", "message":"License acquisition did not work. Acquire a new license or contact the content provider for further assistance."},

0xC00D2720: { "code": "NS_E_DRM_NO_RIGHTS", "message":"The requested operation cannot be performed on this file."},

0xC00D2721: { "code": "NS_E_DRM_KEY_ERROR", "message":"The requested action cannot be performed because a problem occurred with the Windows Media Digital Rights Management (DRM) components on your computer."},

0xC00D2722: { "code": "NS_E_DRM_ENCRYPT_ERROR", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2723: { "code": "NS_E_DRM_DECRYPT_ERROR", "message":"The media file is corrupted. Contact the content provider to get a new file."},

0xC00D2725: { "code": "NS_E_DRM_LICENSE_INVALID_XML", "message":"The license is corrupted. Acquire a new license."},

0xC00D2728: { "code": "NS_E_DRM_NEEDS_INDIVIDUALIZATION", "message":"A security upgrade is required to perform the operation on this media file."},

0xC00D2729: { "code": "NS_E_DRM_ALREADY_INDIVIDUALIZED", "message":"You already have the latest security components. No upgrade is necessary at this time."},

0xC00D272A: { "code": "NS_E_DRM_ACTION_NOT_QUERIED", "message":"The application cannot perform this action. Contact product support for this application."},

0xC00D272B: { "code": "NS_E_DRM_ACQUIRING_LICENSE", "message":"You cannot begin a new license acquisition process until the current one has been completed."},

0xC00D272C: { "code": "NS_E_DRM_INDIVIDUALIZING", "message":"You cannot begin a new security upgrade until the current one has been completed."},

0xC00D272D: { "code": "NS_E_BACKUP_RESTORE_FAILURE", "message":"Failure in Backup-Restore."},

0xC00D272E: { "code": "NS_E_BACKUP_RESTORE_BAD_REQUEST_ID", "message":"Bad Request ID in Backup-Restore."},

0xC00D272F: { "code": "NS_E_DRM_PARAMETERS_MISMATCHED", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2730: { "code": "NS_E_DRM_UNABLE_TO_CREATE_LICENSE_OBJECT", "message":"A license cannot be created for this media file. Reinstall the application."},

0xC00D2731: { "code": "NS_E_DRM_UNABLE_TO_CREATE_INDI_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2732: { "code": "NS_E_DRM_UNABLE_TO_CREATE_ENCRYPT_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2733: { "code": "NS_E_DRM_UNABLE_TO_CREATE_DECRYPT_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2734: { "code": "NS_E_DRM_UNABLE_TO_CREATE_PROPERTIES_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2735: { "code": "NS_E_DRM_UNABLE_TO_CREATE_BACKUP_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2736: { "code": "NS_E_DRM_INDIVIDUALIZE_ERROR", "message":"The security upgrade failed. Try again later."},

0xC00D2737: { "code": "NS_E_DRM_LICENSE_OPEN_ERROR", "message":"License storage is not working. Contact Microsoft product support."},

0xC00D2738: { "code": "NS_E_DRM_LICENSE_CLOSE_ERROR", "message":"License storage is not working. Contact Microsoft product support."},

0xC00D2739: { "code": "NS_E_DRM_GET_LICENSE_ERROR", "message":"License storage is not working. Contact Microsoft product support."},

0xC00D273A: { "code": "NS_E_DRM_QUERY_ERROR", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D273B: { "code": "NS_E_DRM_REPORT_ERROR", "message":"A problem has occurred in the Digital Rights Management component. Contact product support for this application."},

0xC00D273C: { "code": "NS_E_DRM_GET_LICENSESTRING_ERROR", "message":"License storage is not working. Contact Microsoft product support."},

0xC00D273D: { "code": "NS_E_DRM_GET_CONTENTSTRING_ERROR", "message":"The media file is corrupted. Contact the content provider to get a new file."},

0xC00D273E: { "code": "NS_E_DRM_MONITOR_ERROR", "message":"A problem has occurred in the Digital Rights Management component. Try again later."},

0xC00D273F: { "code": "NS_E_DRM_UNABLE_TO_SET_PARAMETER", "message":"The application has made an invalid call to the Digital Rights Management component. Contact product support for this application."},

0xC00D2740: { "code": "NS_E_DRM_INVALID_APPDATA", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2741: { "code": "NS_E_DRM_INVALID_APPDATA_VERSION", "message":"A problem has occurred in the Digital Rights Management component. Contact product support for this application."},

0xC00D2742: { "code": "NS_E_DRM_BACKUP_EXISTS", "message":"Licenses are already backed up in this location."},

0xC00D2743: { "code": "NS_E_DRM_BACKUP_CORRUPT", "message":"One or more backed-up licenses are missing or corrupt."},

0xC00D2744: { "code": "NS_E_DRM_BACKUPRESTORE_BUSY", "message":"You cannot begin a new backup process until the current process has been completed."},

0xC00D2745: { "code": "NS_E_BACKUP_RESTORE_BAD_DATA", "message":"Bad Data sent to Backup-Restore."},

0xC00D2748: { "code": "NS_E_DRM_LICENSE_UNUSABLE", "message":"The license is invalid. Contact the content provider for further assistance."},

0xC00D2749: { "code": "NS_E_DRM_INVALID_PROPERTY", "message":"A required property was not set by the application. Contact product support for this application."},

0xC00D274A: { "code": "NS_E_DRM_SECURE_STORE_NOT_FOUND", "message":"A problem has occurred in the Digital Rights Management component of this application. Try to acquire a license again."},

0xC00D274B: { "code": "NS_E_DRM_CACHED_CONTENT_ERROR", "message":"A license cannot be found for this media file. Use License Management to transfer a license for this file from the original computer, or acquire a new license."},

0xC00D274C: { "code": "NS_E_DRM_INDIVIDUALIZATION_INCOMPLETE", "message":"A problem occurred during the security upgrade. Try again later."},

0xC00D274D: { "code": "NS_E_DRM_DRIVER_AUTH_FAILURE", "message":"Certified driver components are required to play this media file. Contact Windows Update to see whether updated drivers are available for your hardware."},

0xC00D274E: { "code": "NS_E_DRM_NEED_UPGRADE_MSSAP", "message":"One or more of the Secure Audio Path components were not found or an entry point in those components was not found."},

0xC00D274F: { "code": "NS_E_DRM_REOPEN_CONTENT", "message":"Status message: Reopen the file."},

0xC00D2750: { "code": "NS_E_DRM_DRIVER_DIGIOUT_FAILURE", "message":"Certain driver functionality is required to play this media file. Contact Windows Update to see whether updated drivers are available for your hardware."},

0xC00D2751: { "code": "NS_E_DRM_INVALID_SECURESTORE_PASSWORD", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2752: { "code": "NS_E_DRM_APPCERT_REVOKED", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2753: { "code": "NS_E_DRM_RESTORE_FRAUD", "message":"You cannot restore your license(s)."},

0xC00D2754: { "code": "NS_E_DRM_HARDWARE_INCONSISTENT", "message":"The licenses for your media files are corrupted. Contact Microsoft product support."},

0xC00D2755: { "code": "NS_E_DRM_SDMI_TRIGGER", "message":"To transfer this media file, you must upgrade the application."},

0xC00D2756: { "code": "NS_E_DRM_SDMI_NOMORECOPIES", "message":"You cannot make any more copies of this media file."},

0xC00D2757: { "code": "NS_E_DRM_UNABLE_TO_CREATE_HEADER_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2758: { "code": "NS_E_DRM_UNABLE_TO_CREATE_KEYS_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2759: { "code": "NS_E_DRM_LICENSE_NOTACQUIRED", "message":"Unable to obtain license."},

0xC00D275A: { "code": "NS_E_DRM_UNABLE_TO_CREATE_CODING_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D275B: { "code": "NS_E_DRM_UNABLE_TO_CREATE_STATE_DATA_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D275C: { "code": "NS_E_DRM_BUFFER_TOO_SMALL", "message":"The buffer supplied is not sufficient."},

0xC00D275D: { "code": "NS_E_DRM_UNSUPPORTED_PROPERTY", "message":"The property requested is not supported."},

0xC00D275E: { "code": "NS_E_DRM_ERROR_BAD_NET_RESP", "message":"The specified server cannot perform the requested operation."},

0xC00D275F: { "code": "NS_E_DRM_STORE_NOTALLSTORED", "message":"Some of the licenses could not be stored."},

0xC00D2760: { "code": "NS_E_DRM_SECURITY_COMPONENT_SIGNATURE_INVALID", "message":"The Digital Rights Management security upgrade component could not be validated. Contact Microsoft product support."},

0xC00D2761: { "code": "NS_E_DRM_INVALID_DATA", "message":"Invalid or corrupt data was encountered."},

0xC00D2762: { "code": "NS_E_DRM_POLICY_DISABLE_ONLINE", "message":"The Windows Media Digital Rights Management system cannot perform the requested action because your computer or network administrator has enabled the group policy Prevent Windows Media DRM Internet Access. For assistance, contact your administrator."},

0xC00D2763: { "code": "NS_E_DRM_UNABLE_TO_CREATE_AUTHENTICATION_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2764: { "code": "NS_E_DRM_NOT_CONFIGURED", "message":"Not all of the necessary properties for DRM have been set."},

0xC00D2765: { "code": "NS_E_DRM_DEVICE_ACTIVATION_CANCELED", "message":"The portable device does not have the security required to copy protected files to it. To obtain the additional security, try to copy the file to your portable device again. When a message appears, click OK."},

0xC00D2766: { "code": "NS_E_BACKUP_RESTORE_TOO_MANY_RESETS", "message":"Too many resets in Backup-Restore."},

0xC00D2767: { "code": "NS_E_DRM_DEBUGGING_NOT_ALLOWED", "message":"Running this process under a debugger while using DRM content is not allowed."},

0xC00D2768: { "code": "NS_E_DRM_OPERATION_CANCELED", "message":"The user canceled the DRM operation."},

0xC00D2769: { "code": "NS_E_DRM_RESTRICTIONS_NOT_RETRIEVED", "message":"The license you are using has assocaited output restrictions. This license is unusable until these restrictions are queried."},

0xC00D276A: { "code": "NS_E_DRM_UNABLE_TO_CREATE_PLAYLIST_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D276B: { "code": "NS_E_DRM_UNABLE_TO_CREATE_PLAYLIST_BURN_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D276C: { "code": "NS_E_DRM_UNABLE_TO_CREATE_DEVICE_REGISTRATION_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D276D: { "code": "NS_E_DRM_UNABLE_TO_CREATE_METERING_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2770: { "code": "NS_E_DRM_TRACK_EXCEEDED_PLAYLIST_RESTICTION", "message":"The specified track has exceeded it's specified playlist burn limit in this playlist."},

0xC00D2771: { "code": "NS_E_DRM_TRACK_EXCEEDED_TRACKBURN_RESTRICTION", "message":"The specified track has exceeded it's track burn limit."},

0xC00D2772: { "code": "NS_E_DRM_UNABLE_TO_GET_DEVICE_CERT", "message":"A problem has occurred in obtaining the device's certificate. Contact Microsoft product support."},

0xC00D2773: { "code": "NS_E_DRM_UNABLE_TO_GET_SECURE_CLOCK", "message":"A problem has occurred in obtaining the device's secure clock. Contact Microsoft product support."},

0xC00D2774: { "code": "NS_E_DRM_UNABLE_TO_SET_SECURE_CLOCK", "message":"A problem has occurred in setting the device's secure clock. Contact Microsoft product support."},

0xC00D2775: { "code": "NS_E_DRM_UNABLE_TO_GET_SECURE_CLOCK_FROM_SERVER", "message":"A problem has occurred in obtaining the secure clock from server. Contact Microsoft product support."},

0xC00D2776: { "code": "NS_E_DRM_POLICY_METERING_DISABLED", "message":"This content requires the metering policy to be enabled."},

0xC00D2777: { "code": "NS_E_DRM_TRANSFER_CHAINED_LICENSES_UNSUPPORTED", "message":"Transfer of chained licenses unsupported."},

0xC00D2778: { "code": "NS_E_DRM_SDK_VERSIONMISMATCH", "message":"The Digital Rights Management component is not installed properly. Reinstall the Player."},

0xC00D2779: { "code": "NS_E_DRM_LIC_NEEDS_DEVICE_CLOCK_SET", "message":"The file could not be transferred because the device clock is not set."},

0xC00D277A: { "code": "NS_E_LICENSE_HEADER_MISSING_URL", "message":"The content header is missing an acquisition URL."},

0xC00D277B: { "code": "NS_E_DEVICE_NOT_WMDRM_DEVICE", "message":"The current attached device does not support WMDRM."},

0xC00D277C: { "code": "NS_E_DRM_INVALID_APPCERT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D277D: { "code": "NS_E_DRM_PROTOCOL_FORCEFUL_TERMINATION_ON_PETITION", "message":"The client application has been forcefully terminated during a DRM petition."},

0xC00D277E: { "code": "NS_E_DRM_PROTOCOL_FORCEFUL_TERMINATION_ON_CHALLENGE", "message":"The client application has been forcefully terminated during a DRM challenge."},

0xC00D277F: { "code": "NS_E_DRM_CHECKPOINT_FAILED", "message":"Secure storage protection error. Restore your licenses from a previous backup and try again."},

0xC00D2780: { "code": "NS_E_DRM_BB_UNABLE_TO_INITIALIZE", "message":"A problem has occurred in the Digital Rights Management root of trust. Contact Microsoft product support."},

0xC00D2781: { "code": "NS_E_DRM_UNABLE_TO_LOAD_HARDWARE_ID", "message":"A problem has occurred in retrieving the Digital Rights Management machine identification. Contact Microsoft product support."},

0xC00D2782: { "code": "NS_E_DRM_UNABLE_TO_OPEN_DATA_STORE", "message":"A problem has occurred in opening the Digital Rights Management data storage file. Contact Microsoft product."},

0xC00D2783: { "code": "NS_E_DRM_DATASTORE_CORRUPT", "message":"The Digital Rights Management data storage is not functioning properly. Contact Microsoft product support."},

0xC00D2784: { "code": "NS_E_DRM_UNABLE_TO_CREATE_INMEMORYSTORE_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2785: { "code": "NS_E_DRM_STUBLIB_REQUIRED", "message":"A secured library is required to access the requested functionality."},

0xC00D2786: { "code": "NS_E_DRM_UNABLE_TO_CREATE_CERTIFICATE_OBJECT", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2787: { "code": "NS_E_DRM_MIGRATION_TARGET_NOT_ONLINE", "message":"A problem has occurred in the Digital Rights Management component during license migration. Contact Microsoft product support."},

0xC00D2788: { "code": "NS_E_DRM_INVALID_MIGRATION_IMAGE", "message":"A problem has occurred in the Digital Rights Management component during license migration. Contact Microsoft product support."},

0xC00D2789: { "code": "NS_E_DRM_MIGRATION_TARGET_STATES_CORRUPTED", "message":"A problem has occurred in the Digital Rights Management component during license migration. Contact Microsoft product support."},

0xC00D278A: { "code": "NS_E_DRM_MIGRATION_IMPORTER_NOT_AVAILABLE", "message":"A problem has occurred in the Digital Rights Management component during license migration. Contact Microsoft product support."},

0xC00D278B: { "code": "NS_DRM_E_MIGRATION_UPGRADE_WITH_DIFF_SID", "message":"A problem has occurred in the Digital Rights Management component during license migration. Contact Microsoft product support."},

0xC00D278C: { "code": "NS_DRM_E_MIGRATION_SOURCE_MACHINE_IN_USE", "message":"The Digital Rights Management component is in use during license migration. Contact Microsoft product support."},

0xC00D278D: { "code": "NS_DRM_E_MIGRATION_TARGET_MACHINE_LESS_THAN_LH", "message":"Licenses are being migrated to a machine running XP or downlevel OS. This operation can only be performed on Windows Vista or a later OS. Contact Microsoft product support."},

0xC00D278E: { "code": "NS_DRM_E_MIGRATION_IMAGE_ALREADY_EXISTS", "message":"Migration Image already exists. Contact Microsoft product support."},

0xC00D278F: { "code": "NS_E_DRM_HARDWAREID_MISMATCH", "message":"The requested action cannot be performed because a hardware configuration change has been detected by the Windows Media Digital Rights Management (DRM) components on your computer."},

0xC00D2790: { "code": "NS_E_INVALID_DRMV2CLT_STUBLIB", "message":"The wrong stublib has been linked to an application or DLL using drmv2clt.dll."},

0xC00D2791: { "code": "NS_E_DRM_MIGRATION_INVALID_LEGACYV2_DATA", "message":"The legacy V2 data being imported is invalid."},

0xC00D2792: { "code": "NS_E_DRM_MIGRATION_LICENSE_ALREADY_EXISTS", "message":"The license being imported already exists."},

0xC00D2793: { "code": "NS_E_DRM_MIGRATION_INVALID_LEGACYV2_SST_PASSWORD", "message":"The password of the Legacy V2 SST entry being imported is incorrect."},

0xC00D2794: { "code": "NS_E_DRM_MIGRATION_NOT_SUPPORTED", "message":"Migration is not supported by the plugin."},

0xC00D2795: { "code": "NS_E_DRM_UNABLE_TO_CREATE_MIGRATION_IMPORTER_OBJECT", "message":"A migration importer cannot be created for this media file. Reinstall the application."},

0xC00D2796: { "code": "NS_E_DRM_CHECKPOINT_MISMATCH", "message":"The requested action cannot be performed because a problem occurred with the Windows Media Digital Rights Management (DRM) components on your computer."},

0xC00D2797: { "code": "NS_E_DRM_CHECKPOINT_CORRUPT", "message":"The requested action cannot be performed because a problem occurred with the Windows Media Digital Rights Management (DRM) components on your computer."},

0xC00D2798: { "code": "NS_E_REG_FLUSH_FAILURE", "message":"The requested action cannot be performed because a problem occurred with the Windows Media Digital Rights Management (DRM) components on your computer."},

0xC00D2799: { "code": "NS_E_HDS_KEY_MISMATCH", "message":"The requested action cannot be performed because a problem occurred with the Windows Media Digital Rights Management (DRM) components on your computer."},

0xC00D279A: { "code": "NS_E_DRM_MIGRATION_OPERATION_CANCELLED", "message":"Migration was canceled by the user."},

0xC00D279B: { "code": "NS_E_DRM_MIGRATION_OBJECT_IN_USE", "message":"Migration object is already in use and cannot be called until the current operation completes."},

0xC00D279C: { "code": "NS_E_DRM_MALFORMED_CONTENT_HEADER", "message":"The content header does not comply with DRM requirements and cannot be used."},

0xC00D27D8: { "code": "NS_E_DRM_LICENSE_EXPIRED", "message":"The license for this file has expired and is no longer valid. Contact your content provider for further assistance."},

0xC00D27D9: { "code": "NS_E_DRM_LICENSE_NOTENABLED", "message":"The license for this file is not valid yet, but will be at a future date."},

0xC00D27DA: { "code": "NS_E_DRM_LICENSE_APPSECLOW", "message":"The license for this file requires a higher level of security than the player you are currently using has. Try using a different player or download a newer version of your current player."},

0xC00D27DB: { "code": "NS_E_DRM_STORE_NEEDINDI", "message":"The license cannot be stored as it requires security upgrade of Digital Rights Management component."},

0xC00D27DC: { "code": "NS_E_DRM_STORE_NOTALLOWED", "message":"Your machine does not meet the requirements for storing the license."},

0xC00D27DD: { "code": "NS_E_DRM_LICENSE_APP_NOTALLOWED", "message":"The license for this file requires an upgraded version of your player or a different player."},

0xC00D27DF: { "code": "NS_E_DRM_LICENSE_CERT_EXPIRED", "message":"The license server's certificate expired. Make sure your system clock is set correctly. Contact your content provider for further assistance."},

0xC00D27E0: { "code": "NS_E_DRM_LICENSE_SECLOW", "message":"The license for this file requires a higher level of security than the player you are currently using has. Try using a different player or download a newer version of your current player."},

0xC00D27E1: { "code": "NS_E_DRM_LICENSE_CONTENT_REVOKED", "message":"The content owner for the license you just acquired is no longer supporting their content. Contact the content owner for a newer version of the content."},

0xC00D27E2: { "code": "NS_E_DRM_DEVICE_NOT_REGISTERED", "message":"The content owner for the license you just acquired requires your device to register to the current machine."},

0xC00D280A: { "code": "NS_E_DRM_LICENSE_NOSAP", "message":"The license for this file requires a feature that is not supported in your current player or operating system. You can try with newer version of your current player or contact your content provider for further assistance."},

0xC00D280B: { "code": "NS_E_DRM_LICENSE_NOSVP", "message":"The license for this file requires a feature that is not supported in your current player or operating system. You can try with newer version of your current player or contact your content provider for further assistance."},

0xC00D280C: { "code": "NS_E_DRM_LICENSE_NOWDM", "message":"The license for this file requires Windows Driver Model (WDM) audio drivers. Contact your sound card manufacturer for further assistance."},

0xC00D280D: { "code": "NS_E_DRM_LICENSE_NOTRUSTEDCODEC", "message":"The license for this file requires a higher level of security than the player you are currently using has. Try using a different player or download a newer version of your current player."},

0xC00D280E: { "code": "NS_E_DRM_SOURCEID_NOT_SUPPORTED", "message":"The license for this file is not supported by your current player. You can try with newer version of your current player or contact your content provider for further assistance."},

0xC00D283D: { "code": "NS_E_DRM_NEEDS_UPGRADE_TEMPFILE", "message":"An updated version of your media player is required to play the selected content."},

0xC00D283E: { "code": "NS_E_DRM_NEED_UPGRADE_PD", "message":"A new version of the Digital Rights Management component is required. Contact product support for this application to get the latest version."},

0xC00D283F: { "code": "NS_E_DRM_SIGNATURE_FAILURE", "message":"Failed to either create or verify the content header."},

0xC00D2840: { "code": "NS_E_DRM_LICENSE_SERVER_INFO_MISSING", "message":"Could not read the necessary information from the system registry."},

0xC00D2841: { "code": "NS_E_DRM_BUSY", "message":"The DRM subsystem is currently locked by another application or user. Try again later."},

0xC00D2842: { "code": "NS_E_DRM_PD_TOO_MANY_DEVICES", "message":"There are too many target devices registered on the portable media."},

0xC00D2843: { "code": "NS_E_DRM_INDIV_FRAUD", "message":"The security upgrade cannot be completed because the allowed number of daily upgrades has been exceeded. Try again tomorrow."},

0xC00D2844: { "code": "NS_E_DRM_INDIV_NO_CABS", "message":"The security upgrade cannot be completed because the server is unable to perform the operation. Try again later."},

0xC00D2845: { "code": "NS_E_DRM_INDIV_SERVICE_UNAVAILABLE", "message":"The security upgrade cannot be performed because the server is not available. Try again later."},

0xC00D2846: { "code": "NS_E_DRM_RESTORE_SERVICE_UNAVAILABLE", "message":"Windows Media Player cannot restore your licenses because the server is not available. Try again later."},

0xC00D2847: { "code": "NS_E_DRM_CLIENT_CODE_EXPIRED", "message":"Windows Media Player cannot play the protected file. Verify that your computer's date is set correctly. If it is correct, on the Help menu, click Check for Player Updates to install the latest version of the Player."},

0xC00D2848: { "code": "NS_E_DRM_NO_UPLINK_LICENSE", "message":"The chained license cannot be created because the referenced uplink license does not exist."},

0xC00D2849: { "code": "NS_E_DRM_INVALID_KID", "message":"The specified KID is invalid."},

0xC00D284A: { "code": "NS_E_DRM_LICENSE_INITIALIZATION_ERROR", "message":"License initialization did not work. Contact Microsoft product support."},

0xC00D284C: { "code": "NS_E_DRM_CHAIN_TOO_LONG", "message":"The uplink license of a chained license cannot itself be a chained license."},

0xC00D284D: { "code": "NS_E_DRM_UNSUPPORTED_ALGORITHM", "message":"The specified encryption algorithm is unsupported."},

0xC00D284E: { "code": "NS_E_DRM_LICENSE_DELETION_ERROR", "message":"License deletion did not work. Contact Microsoft product support."},

0xC00D28A0: { "code": "NS_E_DRM_INVALID_CERTIFICATE", "message":"The client's certificate is corrupted or the signature cannot be verified."},

0xC00D28A1: { "code": "NS_E_DRM_CERTIFICATE_REVOKED", "message":"The client's certificate has been revoked."},

0xC00D28A2: { "code": "NS_E_DRM_LICENSE_UNAVAILABLE", "message":"There is no license available for the requested action."},

0xC00D28A3: { "code": "NS_E_DRM_DEVICE_LIMIT_REACHED", "message":"The maximum number of devices in use has been reached. Unable to open additional devices."},

0xC00D28A4: { "code": "NS_E_DRM_UNABLE_TO_VERIFY_PROXIMITY", "message":"The proximity detection procedure could not confirm that the receiver is near the transmitter in the network."},

0xC00D28A5: { "code": "NS_E_DRM_MUST_REGISTER", "message":"The client must be registered before executing the intended operation."},

0xC00D28A6: { "code": "NS_E_DRM_MUST_APPROVE", "message":"The client must be approved before executing the intended operation."},

0xC00D28A7: { "code": "NS_E_DRM_MUST_REVALIDATE", "message":"The client must be revalidated before executing the intended operation."},

0xC00D28A8: { "code": "NS_E_DRM_INVALID_PROXIMITY_RESPONSE", "message":"The response to the proximity detection challenge is invalid."},

0xC00D28A9: { "code": "NS_E_DRM_INVALID_SESSION", "message":"The requested session is invalid."},

0xC00D28AA: { "code": "NS_E_DRM_DEVICE_NOT_OPEN", "message":"The device must be opened before it can be used to receive content."},

0xC00D28AB: { "code": "NS_E_DRM_DEVICE_ALREADY_REGISTERED", "message":"Device registration failed because the device is already registered."},

0xC00D28AC: { "code": "NS_E_DRM_UNSUPPORTED_PROTOCOL_VERSION", "message":"Unsupported WMDRM-ND protocol version."},

0xC00D28AD: { "code": "NS_E_DRM_UNSUPPORTED_ACTION", "message":"The requested action is not supported."},

0xC00D28AE: { "code": "NS_E_DRM_CERTIFICATE_SECURITY_LEVEL_INADEQUATE", "message":"The certificate does not have an adequate security level for the requested action."},

0xC00D28AF: { "code": "NS_E_DRM_UNABLE_TO_OPEN_PORT", "message":"Unable to open the specified port for receiving Proximity messages."},

0xC00D28B0: { "code": "NS_E_DRM_BAD_REQUEST", "message":"The message format is invalid."},

0xC00D28B1: { "code": "NS_E_DRM_INVALID_CRL", "message":"The Certificate Revocation List is invalid or corrupted."},

0xC00D28B2: { "code": "NS_E_DRM_ATTRIBUTE_TOO_LONG", "message":"The length of the attribute name or value is too long."},

0xC00D28B3: { "code": "NS_E_DRM_EXPIRED_LICENSEBLOB", "message":"The license blob passed in the cardea request is expired."},

0xC00D28B4: { "code": "NS_E_DRM_INVALID_LICENSEBLOB", "message":"The license blob passed in the cardea request is invalid. Contact Microsoft product support."},

0xC00D28B5: { "code": "NS_E_DRM_INCLUSION_LIST_REQUIRED", "message":"The requested operation cannot be performed because the license does not contain an inclusion list."},

0xC00D28B6: { "code": "NS_E_DRM_DRMV2CLT_REVOKED", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D28B7: { "code": "NS_E_DRM_RIV_TOO_SMALL", "message":"A problem has occurred in the Digital Rights Management component. Contact Microsoft product support."},

0xC00D2904: { "code": "NS_E_OUTPUT_PROTECTION_LEVEL_UNSUPPORTED", "message":"Windows Media Player does not support the level of output protection required by the content."},

0xC00D2905: { "code": "NS_E_COMPRESSED_DIGITAL_VIDEO_PROTECTION_LEVEL_UNSUPPORTED", "message":"Windows Media Player does not support the level of protection required for compressed digital video."},

0xC00D2906: { "code": "NS_E_UNCOMPRESSED_DIGITAL_VIDEO_PROTECTION_LEVEL_UNSUPPORTED", "message":"Windows Media Player does not support the level of protection required for uncompressed digital video."},

0xC00D2907: { "code": "NS_E_ANALOG_VIDEO_PROTECTION_LEVEL_UNSUPPORTED", "message":"Windows Media Player does not support the level of protection required for analog video."},

0xC00D2908: { "code": "NS_E_COMPRESSED_DIGITAL_AUDIO_PROTECTION_LEVEL_UNSUPPORTED", "message":"Windows Media Player does not support the level of protection required for compressed digital audio."},

0xC00D2909: { "code": "NS_E_UNCOMPRESSED_DIGITAL_AUDIO_PROTECTION_LEVEL_UNSUPPORTED", "message":"Windows Media Player does not support the level of protection required for uncompressed digital audio."},

0xC00D290A: { "code": "NS_E_OUTPUT_PROTECTION_SCHEME_UNSUPPORTED", "message":"Windows Media Player does not support the scheme of output protection required by the content."},

0xC00D2AFA: { "code": "NS_E_REBOOT_RECOMMENDED", "message":"Installation was not successful and some file cleanup is not complete. For best results, restart your computer."},

0xC00D2AFB: { "code": "NS_E_REBOOT_REQUIRED", "message":"Installation was not successful. To continue, you must restart your computer."},

0xC00D2AFC: { "code": "NS_E_SETUP_INCOMPLETE", "message":"Installation was not successful."},

0xC00D2AFD: { "code": "NS_E_SETUP_DRM_MIGRATION_FAILED", "message":"Setup cannot migrate the Windows Media Digital Rights Management (DRM) components."},

0xC00D2AFE: { "code": "NS_E_SETUP_IGNORABLE_FAILURE", "message":"Some skin or playlist components cannot be installed."},

0xC00D2AFF: { "code": "NS_E_SETUP_DRM_MIGRATION_FAILED_AND_IGNORABLE_FAILURE", "message":"Setup cannot migrate the Windows Media Digital Rights Management (DRM) components. In addition, some skin or playlist components cannot be installed."},

0xC00D2B00: { "code": "NS_E_SETUP_BLOCKED", "message":"Installation is blocked because your computer does not meet one or more of the setup requirements."},

0xC00D2EE0: { "code": "NS_E_UNKNOWN_PROTOCOL", "message":"The specified protocol is not supported."},

0xC00D2EE1: { "code": "NS_E_REDIRECT_TO_PROXY", "message":"The client is redirected to a proxy server."},

0xC00D2EE2: { "code": "NS_E_INTERNAL_SERVER_ERROR", "message":"The server encountered an unexpected condition which prevented it from fulfilling the request."},

0xC00D2EE3: { "code": "NS_E_BAD_REQUEST", "message":"The request could not be understood by the server."},

0xC00D2EE4: { "code": "NS_E_ERROR_FROM_PROXY", "message":"The proxy experienced an error while attempting to contact the media server."},

0xC00D2EE5: { "code": "NS_E_PROXY_TIMEOUT", "message":"The proxy did not receive a timely response while attempting to contact the media server."},

0xC00D2EE6: { "code": "NS_E_SERVER_UNAVAILABLE", "message":"The server is currently unable to handle the request due to a temporary overloading or maintenance of the server."},

0xC00D2EE7: { "code": "NS_E_REFUSED_BY_SERVER", "message":"The server is refusing to fulfill the requested operation."},

0xC00D2EE8: { "code": "NS_E_INCOMPATIBLE_SERVER", "message":"The server is not a compatible streaming media server."},

0xC00D2EE9: { "code": "NS_E_MULTICAST_DISABLED", "message":"The content cannot be streamed because the Multicast protocol has been disabled."},

0xC00D2EEA: { "code": "NS_E_INVALID_REDIRECT", "message":"The server redirected the player to an invalid location."},

0xC00D2EEB: { "code": "NS_E_ALL_PROTOCOLS_DISABLED", "message":"The content cannot be streamed because all protocols have been disabled."},

0xC00D2EEC: { "code": "NS_E_MSBD_NO_LONGER_SUPPORTED", "message":"The MSBD protocol is no longer supported. Please use HTTP to connect to the Windows Media stream."},

0xC00D2EED: { "code": "NS_E_PROXY_NOT_FOUND", "message":"The proxy server could not be located. Please check your proxy server configuration."},

0xC00D2EEE: { "code": "NS_E_CANNOT_CONNECT_TO_PROXY", "message":"Unable to establish a connection to the proxy server. Please check your proxy server configuration."},

0xC00D2EEF: { "code": "NS_E_SERVER_DNS_TIMEOUT", "message":"Unable to locate the media server. The operation timed out."},

0xC00D2EF0: { "code": "NS_E_PROXY_DNS_TIMEOUT", "message":"Unable to locate the proxy server. The operation timed out."},

0xC00D2EF1: { "code": "NS_E_CLOSED_ON_SUSPEND", "message":"Media closed because Windows was shut down."},

0xC00D2EF2: { "code": "NS_E_CANNOT_READ_PLAYLIST_FROM_MEDIASERVER", "message":"Unable to read the contents of a playlist file from a media server."},

0xC00D2EF3: { "code": "NS_E_SESSION_NOT_FOUND", "message":"Session not found."},

0xC00D2EF4: { "code": "NS_E_REQUIRE_STREAMING_CLIENT", "message":"Content requires a streaming media client."},

0xC00D2EF5: { "code": "NS_E_PLAYLIST_ENTRY_HAS_CHANGED", "message":"A command applies to a previous playlist entry."},

0xC00D2EF6: { "code": "NS_E_PROXY_ACCESSDENIED", "message":"The proxy server is denying access. The username and/or password might be incorrect."},

0xC00D2EF7: { "code": "NS_E_PROXY_SOURCE_ACCESSDENIED", "message":"The proxy could not provide valid authentication credentials to the media server."},

0xC00D2EF8: { "code": "NS_E_NETWORK_SINK_WRITE", "message":"The network sink failed to write data to the network."},

0xC00D2EF9: { "code": "NS_E_FIREWALL", "message":"Packets are not being received from the server. The packets might be blocked by a filtering device, such as a network firewall."},

0xC00D2EFA: { "code": "NS_E_MMS_NOT_SUPPORTED", "message":"The MMS protocol is not supported. Please use HTTP or RTSP to connect to the Windows Media stream."},

0xC00D2EFB: { "code": "NS_E_SERVER_ACCESSDENIED", "message":"The Windows Media server is denying access. The username and/or password might be incorrect."},

0xC00D2EFC: { "code": "NS_E_RESOURCE_GONE", "message":"The Publishing Point or file on the Windows Media Server is no longer available."},

0xC00D2EFD: { "code": "NS_E_NO_EXISTING_PACKETIZER", "message":"There is no existing packetizer plugin for a stream."},

0xC00D2EFE: { "code": "NS_E_BAD_SYNTAX_IN_SERVER_RESPONSE", "message":"The response from the media server could not be understood. This might be caused by an incompatible proxy server or media server."},

0xC00D2F00: { "code": "NS_E_RESET_SOCKET_CONNECTION", "message":"The Windows Media Server reset the network connection."},

0xC00D2F02: { "code": "NS_E_TOO_MANY_HOPS", "message":"The request could not reach the media server (too many hops)."},

0xC00D2F05: { "code": "NS_E_TOO_MUCH_DATA_FROM_SERVER", "message":"The server is sending too much data. The connection has been terminated."},

0xC00D2F06: { "code": "NS_E_CONNECT_TIMEOUT", "message":"It was not possible to establish a connection to the media server in a timely manner. The media server might be down for maintenance, or it might be necessary to use a proxy server to access this media server."},

0xC00D2F07: { "code": "NS_E_PROXY_CONNECT_TIMEOUT", "message":"It was not possible to establish a connection to the proxy server in a timely manner. Please check your proxy server configuration."},

0xC00D2F08: { "code": "NS_E_SESSION_INVALID", "message":"Session not found."},

0xC00D2F0A: { "code": "NS_E_PACKETSINK_UNKNOWN_FEC_STREAM", "message":"Unknown packet sink stream."},

0xC00D2F0B: { "code": "NS_E_PUSH_CANNOTCONNECT", "message":"Unable to establish a connection to the server. Ensure Windows Media Services is started and the HTTP Server control protocol is properly enabled."},

0xC00D2F0C: { "code": "NS_E_INCOMPATIBLE_PUSH_SERVER", "message":"The Server service that received the HTTP push request is not a compatible version of Windows Media Services (WMS). This error might indicate the push request was received by IIS instead of WMS. Ensure WMS is started and has the HTTP Server control protocol properly enabled and try again."},

0xC00D32C8: { "code": "NS_E_END_OF_PLAYLIST", "message":"The playlist has reached its end."},

0xC00D32C9: { "code": "NS_E_USE_FILE_SOURCE", "message":"Use file source."},

0xC00D32CA: { "code": "NS_E_PROPERTY_NOT_FOUND", "message":"The property was not found."},

0xC00D32CC: { "code": "NS_E_PROPERTY_READ_ONLY", "message":"The property is read only."},

0xC00D32CD: { "code": "NS_E_TABLE_KEY_NOT_FOUND", "message":"The table key was not found."},

0xC00D32CF: { "code": "NS_E_INVALID_QUERY_OPERATOR", "message":"Invalid query operator."},

0xC00D32D0: { "code": "NS_E_INVALID_QUERY_PROPERTY", "message":"Invalid query property."},

0xC00D32D2: { "code": "NS_E_PROPERTY_NOT_SUPPORTED", "message":"The property is not supported."},

0xC00D32D4: { "code": "NS_E_SCHEMA_CLASSIFY_FAILURE", "message":"Schema classification failure."},

0xC00D32D5: { "code": "NS_E_METADATA_FORMAT_NOT_SUPPORTED", "message":"The metadata format is not supported."},

0xC00D32D6: { "code": "NS_E_METADATA_NO_EDITING_CAPABILITY", "message":"Cannot edit the metadata."},

0xC00D32D7: { "code": "NS_E_METADATA_CANNOT_SET_LOCALE", "message":"Cannot set the locale id."},

0xC00D32D8: { "code": "NS_E_METADATA_LANGUAGE_NOT_SUPORTED", "message":"The language is not supported in the format."},

0xC00D32D9: { "code": "NS_E_METADATA_NO_RFC1766_NAME_FOR_LOCALE", "message":"There is no RFC1766 name translation for the supplied locale id."},

0xC00D32DA: { "code": "NS_E_METADATA_NOT_AVAILABLE", "message":"The metadata (or metadata item) is not available."},

0xC00D32DB: { "code": "NS_E_METADATA_CACHE_DATA_NOT_AVAILABLE", "message":"The cached metadata (or metadata item) is not available."},

0xC00D32DC: { "code": "NS_E_METADATA_INVALID_DOCUMENT_TYPE", "message":"The metadata document is invalid."},

0xC00D32DD: { "code": "NS_E_METADATA_IDENTIFIER_NOT_AVAILABLE", "message":"The metadata content identifier is not available."},

0xC00D32DE: { "code": "NS_E_METADATA_CANNOT_RETRIEVE_FROM_OFFLINE_CACHE", "message":"Cannot retrieve metadata from the offline metadata cache."},

0xC0261003: { "code": "ERROR_MONITOR_INVALID_DESCRIPTOR_CHECKSUM", "message":"Checksum of the obtained monitor descriptor is invalid."},

0xC0261004: { "code": "ERROR_MONITOR_INVALID_STANDARD_TIMING_BLOCK", "message":"Monitor descriptor contains an invalid standard timing block."},

0xC0261005: { "code": "ERROR_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED", "message":"Windows Management Instrumentation (WMI) data block registration failed for one of the MSMonitorClass WMI subclasses."},

0xC0261006: { "code": "ERROR_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK", "message":"Provided monitor descriptor block is either corrupted or does not contain the monitor's detailed serial number."},

0xC0261007: { "code": "ERROR_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK", "message":"Provided monitor descriptor block is either corrupted or does not contain the monitor's user-friendly name."},

0xC0261008: { "code": "ERROR_MONITOR_NO_MORE_DESCRIPTOR_DATA", "message":"There is no monitor descriptor data at the specified (offset, size) region."},

0xC0261009: { "code": "ERROR_MONITOR_INVALID_DETAILED_TIMING_BLOCK", "message":"Monitor descriptor contains an invalid detailed timing block."},

0xC0262000: { "code": "ERROR_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER", "message":"Exclusive mode ownership is needed to create unmanaged primary allocation."},

0xC0262001: { "code": "ERROR_GRAPHICS_INSUFFICIENT_DMA_BUFFER", "message":"The driver needs more direct memory access (DMA) buffer space to complete the requested operation."},

0xC0262002: { "code": "ERROR_GRAPHICS_INVALID_DISPLAY_ADAPTER", "message":"Specified display adapter handle is invalid."},

0xC0262003: { "code": "ERROR_GRAPHICS_ADAPTER_WAS_RESET", "message":"Specified display adapter and all of its state has been reset."},

0xC0262004: { "code": "ERROR_GRAPHICS_INVALID_DRIVER_MODEL", "message":"The driver stack does not match the expected driver model."},

0xC0262005: { "code": "ERROR_GRAPHICS_PRESENT_MODE_CHANGED", "message":"Present happened but ended up into the changed desktop mode."},

0xC0262006: { "code": "ERROR_GRAPHICS_PRESENT_OCCLUDED", "message":"Nothing to present due to desktop occlusion."},

0xC0262007: { "code": "ERROR_GRAPHICS_PRESENT_DENIED", "message":"Not able to present due to denial of desktop access."},

0xC0262008: { "code": "ERROR_GRAPHICS_CANNOTCOLORCONVERT", "message":"Not able to present with color conversion."},

0xC0262100: { "code": "ERROR_GRAPHICS_NO_VIDEO_MEMORY", "message":"Not enough video memory available to complete the operation."},

0xC0262101: { "code": "ERROR_GRAPHICS_CANT_LOCK_MEMORY", "message":"Could not probe and lock the underlying memory of an allocation."},

0xC0262102: { "code": "ERROR_GRAPHICS_ALLOCATION_BUSY", "message":"The allocation is currently busy."},

0xC0262103: { "code": "ERROR_GRAPHICS_TOO_MANY_REFERENCES", "message":"An object being referenced has reach the maximum reference count already and cannot be referenced further."},

0xC0262104: { "code": "ERROR_GRAPHICS_TRY_AGAIN_LATER", "message":"A problem could not be solved due to some currently existing condition. The problem should be tried again later."},

0xC0262105: { "code": "ERROR_GRAPHICS_TRY_AGAIN_NOW", "message":"A problem could not be solved due to some currently existing condition. The problem should be tried again immediately."},

0xC0262106: { "code": "ERROR_GRAPHICS_ALLOCATION_INVALID", "message":"The allocation is invalid."},

0xC0262107: { "code": "ERROR_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE", "message":"No more unswizzling apertures are currently available."},

0xC0262108: { "code": "ERROR_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED", "message":"The current allocation cannot be unswizzled by an aperture."},

0xC0262109: { "code": "ERROR_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION", "message":"The request failed because a pinned allocation cannot be evicted."},

0xC0262110: { "code": "ERROR_GRAPHICS_INVALID_ALLOCATION_USAGE", "message":"The allocation cannot be used from its current segment location for the specified operation."},

0xC0262111: { "code": "ERROR_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION", "message":"A locked allocation cannot be used in the current command buffer."},

0xC0262112: { "code": "ERROR_GRAPHICS_ALLOCATION_CLOSED", "message":"The allocation being referenced has been closed permanently."},

0xC0262113: { "code": "ERROR_GRAPHICS_INVALID_ALLOCATION_INSTANCE", "message":"An invalid allocation instance is being referenced."},

0xC0262114: { "code": "ERROR_GRAPHICS_INVALID_ALLOCATION_HANDLE", "message":"An invalid allocation handle is being referenced."},

0xC0262115: { "code": "ERROR_GRAPHICS_WRONG_ALLOCATION_DEVICE", "message":"The allocation being referenced does not belong to the current device."},

0xC0262116: { "code": "ERROR_GRAPHICS_ALLOCATION_CONTENT_LOST", "message":"The specified allocation lost its content."},

0xC0262200: { "code": "ERROR_GRAPHICS_GPU_EXCEPTION_ON_DEVICE", "message":"Graphics processing unit (GPU) exception is detected on the given device. The device is not able to be scheduled."},

0xC0262300: { "code": "ERROR_GRAPHICS_INVALID_VIDPN_TOPOLOGY", "message":"Specified video present network (VidPN) topology is invalid."},

0xC0262301: { "code": "ERROR_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED", "message":"Specified VidPN topology is valid but is not supported by this model of the display adapter."},

0xC0262302: { "code": "ERROR_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED", "message":"Specified VidPN topology is valid but is not supported by the display adapter at this time, due to current allocation of its resources."},

0xC0262303: { "code": "ERROR_GRAPHICS_INVALID_VIDPN", "message":"Specified VidPN handle is invalid."},

0xC0262304: { "code": "ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE", "message":"Specified video present source is invalid."},

0xC0262305: { "code": "ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET", "message":"Specified video present target is invalid."},

0xC0262306: { "code": "ERROR_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED", "message":"Specified VidPN modality is not supported (for example, at least two of the pinned modes are not cofunctional)."},

0xC0262308: { "code": "ERROR_GRAPHICS_INVALID_VIDPN_SOURCEMODESET", "message":"Specified VidPN source mode set is invalid."},

0xC0262309: { "code": "ERROR_GRAPHICS_INVALID_VIDPN_TARGETMODESET", "message":"Specified VidPN target mode set is invalid."},

0xC026230A: { "code": "ERROR_GRAPHICS_INVALID_FREQUENCY", "message":"Specified video signal frequency is invalid."},

0xC026230B: { "code": "ERROR_GRAPHICS_INVALID_ACTIVE_REGION", "message":"Specified video signal active region is invalid."},

0xC026230C: { "code": "ERROR_GRAPHICS_INVALID_TOTAL_REGION", "message":"Specified video signal total region is invalid."},

0xC0262310: { "code": "ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE", "message":"Specified video present source mode is invalid."},

0xC0262311: { "code": "ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE", "message":"Specified video present target mode is invalid."},

0xC0262312: { "code": "ERROR_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET", "message":"Pinned mode must remain in the set on VidPN's cofunctional modality enumeration."},

0xC0262313: { "code": "ERROR_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY", "message":"Specified video present path is already in the VidPN topology."},

0xC0262314: { "code": "ERROR_GRAPHICS_MODE_ALREADY_IN_MODESET", "message":"Specified mode is already in the mode set."},

0xC0262315: { "code": "ERROR_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET", "message":"Specified video present source set is invalid."},

0xC0262316: { "code": "ERROR_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET", "message":"Specified video present target set is invalid."},

0xC0262317: { "code": "ERROR_GRAPHICS_SOURCE_ALREADY_IN_SET", "message":"Specified video present source is already in the video present source set."},

0xC0262318: { "code": "ERROR_GRAPHICS_TARGET_ALREADY_IN_SET", "message":"Specified video present target is already in the video present target set."},

0xC0262319: { "code": "ERROR_GRAPHICS_INVALID_VIDPN_PRESENT_PATH", "message":"Specified VidPN present path is invalid."},

0xC026231A: { "code": "ERROR_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY", "message":"Miniport has no recommendation for augmentation of the specified VidPN topology."},

0xC026231B: { "code": "ERROR_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET", "message":"Specified monitor frequency range set is invalid."},

0xC026231C: { "code": "ERROR_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE", "message":"Specified monitor frequency range is invalid."},

0xC026231D: { "code": "ERROR_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET", "message":"Specified frequency range is not in the specified monitor frequency range set."},

0xC026231F: { "code": "ERROR_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET", "message":"Specified frequency range is already in the specified monitor frequency range set."},

0xC0262320: { "code": "ERROR_GRAPHICS_STALE_MODESET", "message":"Specified mode set is stale. Reacquire the new mode set."},

0xC0262321: { "code": "ERROR_GRAPHICS_INVALID_MONITOR_SOURCEMODESET", "message":"Specified monitor source mode set is invalid."},

0xC0262322: { "code": "ERROR_GRAPHICS_INVALID_MONITOR_SOURCE_MODE", "message":"Specified monitor source mode is invalid."},

0xC0262323: { "code": "ERROR_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN", "message":"Miniport does not have any recommendation regarding the request to provide a functional VidPN given the current display adapter configuration."},

0xC0262324: { "code": "ERROR_GRAPHICS_MODE_ID_MUST_BE_UNIQUE", "message":"ID of the specified mode is already used by another mode in the set."},

0xC0262325: { "code": "ERROR_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION", "message":"System failed to determine a mode that is supported by both the display adapter and the monitor connected to it."},

0xC0262326: { "code": "ERROR_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES", "message":"Number of video present targets must be greater than or equal to the number of video present sources."},

0xC0262327: { "code": "ERROR_GRAPHICS_PATH_NOT_IN_TOPOLOGY", "message":"Specified present path is not in the VidPN topology."},

0xC0262328: { "code": "ERROR_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE", "message":"Display adapter must have at least one video present source."},

0xC0262329: { "code": "ERROR_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET", "message":"Display adapter must have at least one video present target."},

0xC026232A: { "code": "ERROR_GRAPHICS_INVALID_MONITORDESCRIPTORSET", "message":"Specified monitor descriptor set is invalid."},

0xC026232B: { "code": "ERROR_GRAPHICS_INVALID_MONITORDESCRIPTOR", "message":"Specified monitor descriptor is invalid."},

0xC026232C: { "code": "ERROR_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET", "message":"Specified descriptor is not in the specified monitor descriptor set."},

0xC026232D: { "code": "ERROR_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET", "message":"Specified descriptor is already in the specified monitor descriptor set."},

0xC026232E: { "code": "ERROR_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE", "message":"ID of the specified monitor descriptor is already used by another descriptor in the set."},

0xC026232F: { "code": "ERROR_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE", "message":"Specified video present target subset type is invalid."},

0xC0262330: { "code": "ERROR_GRAPHICS_RESOURCES_NOT_RELATED", "message":"Two or more of the specified resources are not related to each other, as defined by the interface semantics."},

0xC0262331: { "code": "ERROR_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE", "message":"ID of the specified video present source is already used by another source in the set."},

0xC0262332: { "code": "ERROR_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE", "message":"ID of the specified video present target is already used by another target in the set."},

0xC0262333: { "code": "ERROR_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET", "message":"Specified VidPN source cannot be used because there is no available VidPN target to connect it to."},

0xC0262334: { "code": "ERROR_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER", "message":"Newly arrived monitor could not be associated with a display adapter."},

0xC0262335: { "code": "ERROR_GRAPHICS_NO_VIDPNMGR", "message":"Display adapter in question does not have an associated VidPN manager."},

0xC0262336: { "code": "ERROR_GRAPHICS_NO_ACTIVE_VIDPN", "message":"VidPN manager of the display adapter in question does not have an active VidPN."},

0xC0262337: { "code": "ERROR_GRAPHICS_STALE_VIDPN_TOPOLOGY", "message":"Specified VidPN topology is stale. Re-acquire the new topology."},

0xC0262338: { "code": "ERROR_GRAPHICS_MONITOR_NOT_CONNECTED", "message":"There is no monitor connected on the specified video present target."},

0xC0262339: { "code": "ERROR_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY", "message":"Specified source is not part of the specified VidPN topology."},

0xC026233A: { "code": "ERROR_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE", "message":"Specified primary surface size is invalid."},

0xC026233B: { "code": "ERROR_GRAPHICS_INVALID_VISIBLEREGION_SIZE", "message":"Specified visible region size is invalid."},

0xC026233C: { "code": "ERROR_GRAPHICS_INVALID_STRIDE", "message":"Specified stride is invalid."},

0xC026233D: { "code": "ERROR_GRAPHICS_INVALID_PIXELFORMAT", "message":"Specified pixel format is invalid."},

0xC026233E: { "code": "ERROR_GRAPHICS_INVALID_COLORBASIS", "message":"Specified color basis is invalid."},

0xC026233F: { "code": "ERROR_GRAPHICS_INVALID_PIXELVALUEACCESSMODE", "message":"Specified pixel value access mode is invalid."},

0xC0262340: { "code": "ERROR_GRAPHICS_TARGET_NOT_IN_TOPOLOGY", "message":"Specified target is not part of the specified VidPN topology."},

0xC0262341: { "code": "ERROR_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT", "message":"Failed to acquire display mode management interface."},

0xC0262342: { "code": "ERROR_GRAPHICS_VIDPN_SOURCE_IN_USE", "message":"Specified VidPN source is already owned by a display mode manager (DMM) client and cannot be used until that client releases it."},

0xC0262343: { "code": "ERROR_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN", "message":"Specified VidPN is active and cannot be accessed."},

0xC0262344: { "code": "ERROR_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL", "message":"Specified VidPN present path importance ordinal is invalid."},

0xC0262345: { "code": "ERROR_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION", "message":"Specified VidPN present path content geometry transformation is invalid."},

0xC0262346: { "code": "ERROR_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED", "message":"Specified content geometry transformation is not supported on the respective VidPN present path."},

0xC0262347: { "code": "ERROR_GRAPHICS_INVALID_GAMMA_RAMP", "message":"Specified gamma ramp is invalid."},

0xC0262348: { "code": "ERROR_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED", "message":"Specified gamma ramp is not supported on the respective VidPN present path."},

0xC0262349: { "code": "ERROR_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED", "message":"Multisampling is not supported on the respective VidPN present path."},

0xC026234A: { "code": "ERROR_GRAPHICS_MODE_NOT_IN_MODESET", "message":"Specified mode is not in the specified mode set."},

0xC026234D: { "code": "ERROR_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON", "message":"Specified VidPN topology recommendation reason is invalid."},

0xC026234E: { "code": "ERROR_GRAPHICS_INVALID_PATH_CONTENT_TYPE", "message":"Specified VidPN present path content type is invalid."},

0xC026234F: { "code": "ERROR_GRAPHICS_INVALID_COPYPROTECTION_TYPE", "message":"Specified VidPN present path copy protection type is invalid."},

0xC0262350: { "code": "ERROR_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS", "message":"No more than one unassigned mode set can exist at any given time for a given VidPN source or target."},

0xC0262352: { "code": "ERROR_GRAPHICS_INVALID_SCANLINE_ORDERING", "message":"The specified scan line ordering type is invalid."},

0xC0262353: { "code": "ERROR_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED", "message":"Topology changes are not allowed for the specified VidPN."},

0xC0262354: { "code": "ERROR_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS", "message":"All available importance ordinals are already used in the specified topology."},

0xC0262355: { "code": "ERROR_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT", "message":"Specified primary surface has a different private format attribute than the current primary surface."},

0xC0262356: { "code": "ERROR_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM", "message":"Specified mode pruning algorithm is invalid."},

0xC0262400: { "code": "ERROR_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED", "message":"Specified display adapter child device already has an external device connected to it."},

0xC0262401: { "code": "ERROR_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED", "message":"The display adapter child device does not support reporting a descriptor."},

0xC0262430: { "code": "ERROR_GRAPHICS_NOT_A_LINKED_ADAPTER", "message":"The display adapter is not linked to any other adapters."},

0xC0262431: { "code": "ERROR_GRAPHICS_LEADLINK_NOT_ENUMERATED", "message":"Lead adapter in a linked configuration was not enumerated yet."},

0xC0262432: { "code": "ERROR_GRAPHICS_CHAINLINKS_NOT_ENUMERATED", "message":"Some chain adapters in a linked configuration were not enumerated yet."},

0xC0262433: { "code": "ERROR_GRAPHICS_ADAPTER_CHAIN_NOT_READY", "message":"The chain of linked adapters is not ready to start because of an unknown failure."},

0xC0262434: { "code": "ERROR_GRAPHICS_CHAINLINKS_NOT_STARTED", "message":"An attempt was made to start a lead link display adapter when the chain links were not started yet."},

0xC0262435: { "code": "ERROR_GRAPHICS_CHAINLINKS_NOT_POWERED_ON", "message":"An attempt was made to turn on a lead link display adapter when the chain links were turned off."},

0xC0262436: { "code": "ERROR_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE", "message":"The adapter link was found to be in an inconsistent state. Not all adapters are in an expected PNP or power state."},

0xC0262438: { "code": "ERROR_GRAPHICS_NOT_POST_DEVICE_DRIVER", "message":"The driver trying to start is not the same as the driver for the posted display adapter."},

0xC0262500: { "code": "ERROR_GRAPHICS_OPM_NOT_SUPPORTED", "message":"The driver does not support Output Protection Manager (OPM)."},

0xC0262501: { "code": "ERROR_GRAPHICS_COPP_NOT_SUPPORTED", "message":"The driver does not support Certified Output Protection Protocol (COPP)."},

0xC0262502: { "code": "ERROR_GRAPHICS_UAB_NOT_SUPPORTED", "message":"The driver does not support a user-accessible bus (UAB)."},

0xC0262503: { "code": "ERROR_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS", "message":"The specified encrypted parameters are invalid."},

0xC0262504: { "code": "ERROR_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL", "message":"An array passed to a function cannot hold all of the data that the function wants to put in it."},

0xC0262505: { "code": "ERROR_GRAPHICS_OPM_NO_VIDEO_OUTPUTS_EXIST", "message":"The GDI display device passed to this function does not have any active video outputs."},

0xC0262506: { "code": "ERROR_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME", "message":"The protected video path (PVP) cannot find an actual GDI display device that corresponds to the passed-in GDI display device name."},

0xC0262507: { "code": "ERROR_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP", "message":"This function failed because the GDI display device passed to it was not attached to the Windows desktop."},

0xC0262508: { "code": "ERROR_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED", "message":"The PVP does not support mirroring display devices because they do not have video outputs."},

0xC026250A: { "code": "ERROR_GRAPHICS_OPM_INVALID_POINTER", "message":"The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, it points to an invalid address, it points to a kernel mode address, or it is not correctly aligned."},

0xC026250B: { "code": "ERROR_GRAPHICS_OPM_INTERNAL_ERROR", "message":"An internal error caused this operation to fail."},

0xC026250C: { "code": "ERROR_GRAPHICS_OPM_INVALID_HANDLE", "message":"The function failed because the caller passed in an invalid OPM user mode handle."},

0xC026250D: { "code": "ERROR_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE", "message":"This function failed because the GDI device passed to it did not have any monitors associated with it."},

0xC026250E: { "code": "ERROR_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH", "message":"A certificate could not be returned because the certificate buffer passed to the function was too small."},

0xC026250F: { "code": "ERROR_GRAPHICS_OPM_SPANNING_MODE_ENABLED", "message":"A video output could not be created because the frame buffer is in spanning mode."},

0xC0262510: { "code": "ERROR_GRAPHICS_OPM_THEATER_MODE_ENABLED", "message":"A video output could not be created because the frame buffer is in theater mode."},

0xC0262511: { "code": "ERROR_GRAPHICS_PVP_HFS_FAILED", "message":"The function call failed because the display adapter's hardware functionality scan failed to validate the graphics hardware."},

0xC0262512: { "code": "ERROR_GRAPHICS_OPM_INVALID_SRM", "message":"The High-Bandwidth Digital Content Protection (HDCP) System Renewability Message (SRM) passed to this function did not comply with section 5 of the HDCP 1.1 specification."},

0xC0262513: { "code": "ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP", "message":"The video output cannot enable the HDCP system because it does not support it."},

0xC0262514: { "code": "ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP", "message":"The video output cannot enable analog copy protection because it does not support it."},

0xC0262515: { "code": "ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA", "message":"The video output cannot enable the Content Generation Management System Analog (CGMS-A) protection technology because it does not support it."},

0xC0262516: { "code": "ERROR_GRAPHICS_OPM_HDCP_SRM_NEVER_SET", "message":"IOPMVideoOutput's GetInformation() method cannot return the version of the SRM being used because the application never successfully passed an SRM to the video output."},

0xC0262517: { "code": "ERROR_GRAPHICS_OPM_RESOLUTION_TOO_HIGH", "message":"IOPMVideoOutput's Configure() method cannot enable the specified output protection technology because the output's screen resolution is too high."},

0xC0262518: { "code": "ERROR_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE", "message":"IOPMVideoOutput's Configure() method cannot enable HDCP because the display adapter's HDCP hardware is already being used by other physical outputs."},

0xC0262519: { "code": "ERROR_GRAPHICS_OPM_VIDEO_OUTPUT_NO_LONGER_EXISTS", "message":"The operating system asynchronously destroyed this OPM video output because the operating system's state changed. This error typically occurs because the monitor physical device object (PDO) associated with this video output was removed, the monitor PDO associated with this video output was stopped, the video output's session became a nonconsole session or the video output's desktop became an inactive desktop."},

0xC026251A: { "code": "ERROR_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS", "message":"IOPMVideoOutput's methods cannot be called when a session is changing its type. There are currently three types of sessions: console, disconnected and remote (remote desktop protocol [RDP] or Independent Computing Architecture [ICA])."},

0xC0262580: { "code": "ERROR_GRAPHICS_I2C_NOT_SUPPORTED", "message":"The monitor connected to the specified video output does not have an I2C bus."},

0xC0262581: { "code": "ERROR_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST", "message":"No device on the I2C bus has the specified address."},

0xC0262582: { "code": "ERROR_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA", "message":"An error occurred while transmitting data to the device on the I2C bus."},

0xC0262583: { "code": "ERROR_GRAPHICS_I2C_ERROR_RECEIVING_DATA", "message":"An error occurred while receiving data from the device on the I2C bus."},

0xC0262584: { "code": "ERROR_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED", "message":"The monitor does not support the specified Virtual Control Panel (VCP) code."},

0xC0262585: { "code": "ERROR_GRAPHICS_DDCCI_INVALID_DATA", "message":"The data received from the monitor is invalid."},

0xC0262586: { "code": "ERROR_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE", "message":"A function call failed because a monitor returned an invalid Timing Status byte when the operating system used the Display Data Channel Command Interface (DDC/CI) Get Timing Report and Timing Message command to get a timing report from a monitor."},

0xC0262587: { "code": "ERROR_GRAPHICS_MCA_INVALID_CAPABILITIES_STRING", "message":"The monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1 or MCCS 2 Revision 1 specification."},

0xC0262588: { "code": "ERROR_GRAPHICS_MCA_INTERNAL_ERROR", "message":"An internal Monitor Configuration API error occurred."},

0xC0262589: { "code": "ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND", "message":"An operation failed because a DDC/CI message had an invalid value in its command field."},

0xC026258A: { "code": "ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH", "message":"This error occurred because a DDC/CI message length field contained an invalid value."},

0xC026258B: { "code": "ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM", "message":"This error occurred because the value in a DDC/CI message checksum field did not match the message's computed checksum value. This error implies that the data was corrupted while it was being transmitted from a monitor to a computer."},

0xC02625D6: { "code": "ERROR_GRAPHICS_PMEA_INVALID_MONITOR", "message":"The HMONITOR no longer exists, is not attached to the desktop, or corresponds to a mirroring device."},

0xC02625D7: { "code": "ERROR_GRAPHICS_PMEA_INVALID_D3D_DEVICE", "message":"The Direct3D (D3D) device's GDI display device no longer exists, is not attached to the desktop, or is a mirroring display device."},

0xC02625D8: { "code": "ERROR_GRAPHICS_DDCCI_CURRENT_CURRENT_VALUE_GREATER_THAN_MAXIMUM_VALUE", "message":"A continuous VCP code's current value is greater than its maximum value. This error code indicates that a monitor returned an invalid value."},

0xC02625D9: { "code": "ERROR_GRAPHICS_MCA_INVALID_VCP_VERSION", "message":"The monitor's VCP Version (0xDF) VCP code returned an invalid version value."},

0xC02625DA: { "code": "ERROR_GRAPHICS_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION", "message":"The monitor does not comply with the Monitor Control Command Set (MCCS) specification it claims to support."},

0xC02625DB: { "code": "ERROR_GRAPHICS_MCA_MCCS_VERSION_MISMATCH", "message":"The MCCS version in a monitor's mccs_ver capability does not match the MCCS version the monitor reports when the VCP Version (0xDF) VCP code is used."},

0xC02625DC: { "code": "ERROR_GRAPHICS_MCA_UNSUPPORTED_MCCS_VERSION", "message":"The Monitor Configuration API only works with monitors that support the MCCS 1.0 specification, the MCCS 2.0 specification, or the MCCS 2.0 Revision 1 specification."},

0xC02625DE: { "code": "ERROR_GRAPHICS_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED", "message":"The monitor returned an invalid monitor technology type. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification."},

0xC02625DF: { "code": "ERROR_GRAPHICS_MCA_UNSUPPORTED_COLOR_TEMPERATURE", "message":"The SetMonitorColorTemperature() caller passed a color temperature to it that the current monitor did not support. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification."},

0xC02625E0: { "code": "ERROR_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED", "message":"This function can be used only if a program is running in the local console session. It cannot be used if the program is running on a remote desktop session or on a terminal server session."},
}

WINERROR = {
    **WIN32ERROR,
    **HRESULT,
}