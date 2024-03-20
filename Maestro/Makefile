all:
	(cat template.asm ; python x.py ) > x.asm
	nasm -f bin x.asm -o exp
run:
	./run.sh exp