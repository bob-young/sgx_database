
######### SQLITE3 SUPPORT ########
#SQLITE3_SUPPORT ?= 0
SQLITE3_SUPPORT ?= 1
SQLITE3_OPT_CONFIG := -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_OMIT_LOCALTIME -DSQLITE_DEFAULT_MMAP_SIZE=0 -DSQLITE_HAS_CODEC
VFS_SGX_TEST ?= 0

#####################################
######### IPP Settings  ##########
IPP_Include_Path := /opt/intel/compilers_and_libraries_2018.1.163/linux/ippcp/include/
IPP_Link_Path := /opt/intel/compilers_and_libraries_2018.1.163/linux/ippcp/lib/intel64_lin/
IPP_Link_Flag := -L$(IPP_Link_Path) -lippcp 
IPP_Link_Static := -L./TrustedLib -lippcp

#####################################
######### SGX SDK Settings ##########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/sqlite3Client.cpp $(wildcard App/vfslib/*.cpp) $(wildcard App/ipp/*.cpp) 
#App/sqlite3Client.cpp
# $(wildcard App/Edger8rSyntax/*.cpp) $(wildcard App/TrustedLibrary/*.cpp)
App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include -IApp/ipp -IApp/enclave -I$(IPP_Include_Path)

App_C_Flags := $(SGX_COMMON_CFLAGS) -lcrypto -fPIC -Wno-attributes $(App_Include_Paths) 

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

ifeq ($(SQLITE3_SUPPORT), 1)
ifeq ($(VFS_SGX_TEST), 1)
        App_C_Flags += -DVFS_SGX_TEST
endif
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) $(IPP_Link_Static) -lpthread -lcrypto

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := sqlite3Client

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard Enclave/*.cpp) $(wildcard Enclave/vfslib/*.cpp) $(wildcard Enclave/tstl2cl/*.cpp) $(wildcard Enclave/ipp/*.cpp) $(wildcard Enclave/interface/*.cpp) 
#Enclave/Enclave.cpp
# $(wildcard Enclave/Edger8rSyntax/*.cpp) $(wildcard Enclave/TrustedLibrary/*.cpp)
Enclave_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -IEnclave/ipp -I$(IPP_Include_Path) -IEnclave/interface

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
ifeq ($(SQLITE3_SUPPORT), 1)
ifeq ($(VFS_SGX_TEST), 1)
        Enclave_C_Flags += -fno-builtin -DSQLITE_SGX_SUPPORT -DVFS_SGX_TEST
else
        Enclave_C_Flags += -fno-builtin -DSQLITE_SGX_SUPPORT
endif
endif
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave/Enclave.lds
	

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

App/oss_test.o: App/oss_test.c App/oss_test.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


$(App_Name): App/Enclave_u.o $(App_Cpp_Objects) App/oss_test.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/sqlite3.o: Enclave/sqlite3.c 
### Enclave/sqlite3secure.c Enclave/sha2.c Enclave/rijndael.c Enclave/codec.c Enclave/codecext.c ###
	@$(CC) $(Enclave_C_Flags) ${SQLITE3_OPT_CONFIG} -c $< -o $@
	@echo "CC   <=  $<"

Enclave/hashmap.o: Enclave/hashmap/hashmap.c Enclave/hashmap/hashmap.h
	@$(CC) $(Enclave_C_Flags) ${SQLITE3_OPT_CONFIG} -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

ifeq ($(SQLITE3_SUPPORT), 1)
$(Enclave_Name): Enclave/Enclave_t.o Enclave/sqlite3.o Enclave/hashmap.o $(Enclave_Cpp_Objects)
else
$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@echo "SQLITE3 not SUPPORTED!"
endif
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags) $(IPP_Link_Flag)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/oss_test.o App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* Enclave/sqlite3.o Enclave/c_map.o Enclave/c_tree.o Enclave/c_list.o Enclave/c_stack.o Enclave/c_iterator.o Enclave/c_queue.o Enclave/c_set.o Enclave/c_pair.o Enclave/c_vector.o Enclave/c_memory.o Enclave/c_function.o Enclave/c_algo.o
	
