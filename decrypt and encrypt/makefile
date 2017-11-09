JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	decrypt.java \
	encrypt.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
	$(RM) custom_ciphertext
	$(RM) padded_plaintext
	$(RM) ciphertext
