
TESTDIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

%.class : %.java
	javac $<

%.dex : %.class
	${TESTDIR}/../android-sdk/build-tools/28.0.3/dx --dex --output=$@ $<


.PHONY : Min
Min : Min.class Min.dex

.PHONY : Debug
Debug :
	javac Debug.java
	${TESTDIR}/../android-sdk/build-tools/28.0.3/dx --dex --no-optimize --output=Debug.dex Debug\$$Nested.class Debug.class


.PHONY : clean
clean :
	rm -f *.dex *.class
