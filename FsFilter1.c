//#include <ntddk.h>
#include <Fltkernel.h>
#pragma comment(lib, "FltMgr.lib")

UNICODE_STRING fileNameToBeHide = RTL_CONSTANT_STRING(L"C:\\Users\\void\\Desktop\\file.txt");

PFLT_FILTER filter = NULL;

FLT_PREOP_CALLBACK_STATUS PfltPreOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext) {
	PFLT_FILE_NAME_INFORMATION fileNameInfo;
	if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo))) {
		FltParseFileNameInformation(fileNameInfo);
		if (RtlCompareUnicodeString(&fileNameInfo->Name.Buffer, &fileNameToBeHide, 0)) {
			KdPrint(("File created.\n"));
		}
	}
}
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
	KdPrint(("Unload called.\n"));
	FltUnregisterFilter(filter);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath) {
	NTSTATUS status;
	const FLT_OPERATION_REGISTRATION CallBacks[2] =
	{
		{ IRP_MJ_CREATE ,0,PfltPreOperationCallback ,0 },
		{ IRP_MJ_OPERATION_END }
	};
	const FLT_REGISTRATION fltReg = { sizeof(FLT_REGISTRATION),0
		,CallBacks,MiniUnload,0,0,0,0,0,0,0,0 };

	status = FltRegisterFilter(driverObject, &fltReg, &filter);
	if (!NT_SUCCESS(status)) {
		KdPrint(("FltRegister failed.\n"));
		return status;
	}
	status = FltStartFiltering(filter);
	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(filter);
		KdPrint(("Fltstart failed.\n"));
		return status;
	}
	return STATUS_SUCCESS;
}