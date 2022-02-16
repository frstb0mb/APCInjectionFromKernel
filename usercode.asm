.code

LoadLibrary_stub proc
	mov rax, 0
	push rax					; \0
	mov rdx, 6C6C642E74736574h
	push rdx					; test.dll
	mov rdx, rcx				; LoadLibraryA
	mov rcx, rsp
	sub rsp, 20h ; shadow space
	call rdx
	add rsp, 30h
	ret
LoadLibrary_stub endp

end