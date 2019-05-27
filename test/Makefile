
TESTDIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

%.class : %.java
	javac $<

%.dex : %.class
	${TESTDIR}/../android-sdk/build-tools/28.0.3/dx --dex --no-optimize --output=$@ $<


Min : Min.class Min.dex


.PHONY : clean
clean :
	rm -f *.dex *.class
