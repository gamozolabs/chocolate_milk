SERVER = 192.168.122.21
#SERVER = REDMOND\\brfalk@192.168.100.129

all:
	scp -r ../sausage_factory $(SERVER):
	ssh $(SERVER) -t '\"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat\" x64 && cd sausage_factory && nmake -f Makefile.win'

