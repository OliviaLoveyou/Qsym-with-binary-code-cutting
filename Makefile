AFL_ROOT=/home/yk/afl-2.52b
INPUT=/home/yk/input/
OUTPUT=/home/yk/output/
AFL_CMDLINE=/home/yk/example/test
QSYM_CMDLINE=/home/yk/example/test-no

export:
	export AFL_ROOT=$(AFL_ROOT)
	export INPUT=$(INPUT)
	export OUTPUT=$(OUTPUT)
	export AFL_CMDLINE=$(AFL_CMDLINE)
	export QSYM_CMDLINE=$(QSYM_CMDLINE)
clean:
	rm -rf $(OUTPUT)*
