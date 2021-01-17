ROOT_DIR:= ./

INC_DIR:= $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/include/* \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/os_adapter/include/* \
      $(ROOT_DIR)/foundation/communication/interfaces/kits/softbus_lite/discovery/* \
      $(ROOT_DIR)/third_party/cJSON/* \
      $(ROOT_DIR)/third_party/bounds_checking_function/include/* \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/discovery_service/include/* \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/authmanager/include/* \
      $(ROOT_DIR)/base/startup/interfaces/kits/syspara_lite/* \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/include/libdistbus/* \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/include/utils/* \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/libdistbus/* \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/utils/* \
      $(ROOT_DIR)/foundation/communication/interfaces/kits/softbus_lite/transport/* \
      $(ROOT_DIR)/base/security/interfaces/innerkits/hichainsdk_lite/* \
      $(ROOT_DIR)/third_party/mbedtls/include/* \
      $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/huks_adapter/* \
      $(ROOT_DIR)/base/security/interfaces/kits/iam_lite/*

INC_DIR_SOFTBUS:= $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/include \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/os_adapter/include \
      $(ROOT_DIR)/foundation/communication/interfaces/kits/softbus_lite/discovery \
      $(ROOT_DIR)/third_party/cJSON \
      $(ROOT_DIR)/third_party/bounds_checking_function/include \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/discovery_service/include \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/authmanager/include \
      $(ROOT_DIR)/base/startup/interfaces/kits/syspara_lite \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/include/libdistbus \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/include/utils \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/libdistbus \
      $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/utils \
      $(ROOT_DIR)/foundation/communication/interfaces/kits/softbus_lite/transport \
      $(ROOT_DIR)/base/security/interfaces/innerkits/hichainsdk_lite \
      $(ROOT_DIR)/third_party/mbedtls/include \
      $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/huks_adapter/ \
      $(ROOT_DIR)/base/security/interfaces/kits/iam_lite 
SRCS_SOFTBUS:=  $(ROOT_DIR)/foundation/communication/services/softbus_lite/authmanager/source/auth_conn.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/authmanager/source/auth_interface.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/authmanager/source/bus_manager.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/authmanager/source/msg_get_deviceid.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/authmanager/source/wifi_auth_manager.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/source/coap_adapter.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/source/coap_discover.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/source/coap_socket.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/source/json_payload.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/source/nstackx_common.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/coap/source/nstackx_device.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/discovery_service/source/coap_service.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/discovery_service/source/common_info_manager.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/discovery/discovery_service/source/discovery_service.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/os_adapter/source/L1/os_adapter.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/libdistbus/auth_conn_manager.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/libdistbus/tcp_session.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/libdistbus/tcp_session_manager.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/libdistbus/trans_lock.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/utils/aes_gcm.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/utils/message.c \
    $(ROOT_DIR)/foundation/communication/services/softbus_lite/trans_service/source/utils/tcp_socket.c 
OBJS_SOFTBUS:= $(patsubst %.c, %.o, $(SRCS_SOFTBUS))

INC_DIR_HICHAINSDK:=   $(ROOT_DIR)/third_party/bounds_checking_function/include \
        $(ROOT_DIR)/base/security/interfaces/innerkits/hichainsdk_lite \
        $(ROOT_DIR)/third_party/cJSON \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/base \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/huks_adapter \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/json \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/log \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/schedule \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct \
        $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info 
SRCS_HICHAINSDK:= $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info/add_auth_info.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info/add_auth_info_client.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info/auth_info.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info/exchange_auth_info.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info/exchange_auth_info_client.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info/remove_auth_info_client.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/auth_info/remove_auth_info.c \
	$(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/hichain.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/huks_adapter/huks_adapter.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/json/commonutil.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/json/jsonutil.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/key_agreement.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/key_agreement_client.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/key_agreement_server.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/pake_client.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/pake_server.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/sec_clone_server.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/sts_client.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/key_agreement/sts_server.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/log/log.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/schedule/build_object.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/schedule/distribution.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/add_auth_info_data.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/add_auth_info_request.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/add_auth_info_response.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/auth_ack_request.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/auth_ack_response.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/auth_start_request.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/auth_start_response.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/exchange_auth_data.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/exchange_request.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/exchange_response.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/import_add_auth_data.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/inform_message.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/key_agreement_version.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/pake_client_confirm.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/pake_request.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/pake_response.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/pake_server_confirm.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/parsedata.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/rmv_auth_info_data.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/rmv_auth_info_request.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/rmv_auth_info_response.c \
    $(ROOT_DIR)/base/security/frameworks/hichainsdk_lite/source/struct/sec_clone_data.c 
OBJS_HICHAINSDK:= $(patsubst %.c, %.o, $(SRCS_HICHAINSDK))


INC_DIR_OPENSSL:= $(ROOT_DIR)/third_party/openssl/include \
        $(ROOT_DIR)/third_party/openssl/crypto/include \
        $(ROOT_DIR)/third_party/openssl/crypto/ec \
        $(ROOT_DIR)/third_party/openssl/ 
SRCS_OPENSSL:= $(ROOT_DIR)/third_party/openssl/crypto/cryptlib.c \
    $(ROOT_DIR)/third_party/openssl/crypto/ec/curve25519.c \
    $(ROOT_DIR)/third_party/openssl/crypto/mem_clr.c \
    $(ROOT_DIR)/third_party/openssl/crypto/sha/sha512.c 
OBJS_OPENSSL:= $(patsubst %.c, %.o, $(SRCS_OPENSSL))


INC_DIR_HUKS:=  $(ROOT_DIR)/base/security/frameworks/huks_lite/source/ \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/common \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/soft_service \
    $(ROOT_DIR)/third_party/bounds_checking_function/include \
    $(ROOT_DIR)/base/security/interfaces/innerkits/huks_lite \
    $(ROOT_DIR)/third_party/mbedtls/include \
    $(ROOT_DIR)/third_party/openssl/crypto/ec \
    $(ROOT_DIR)/third_party/openssl/include 
SRCS_HUKS:= $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/common/hks_bn.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/common/hks_common.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/common/hks_hardware_random.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/common/hks_log_utils.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/common/hks_mem.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/common/hks_utility.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/soft_service/hks_file.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/soft_service/hks_file_liteos.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/soft_service/hks_rkc.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/soft_service/hks_service.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/soft_service/hks_storage.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/hks_access.c \
    $(ROOT_DIR)/base/security/frameworks/huks_lite/source/hw_keystore_sdk/hks_client.c
OBJS_HUKS:= $(patsubst %.c, %.o, $(SRCS_HUKS))

INC_DIR_MBEDTLS:= $(ROOT_DIR)/third_party/mbedtls/include
SRCS_MBEDTLS:= $(wildcard $(ROOT_DIR)/third_party/mbedtls/library/*.c)
OBJS_MBEDTLS:= $(patsubst %.c, %.o, $(SRCS_MBEDTLS))

INC_DIR_CJSON:=$(ROOT_DIR)/third_party/cJSON
SRCS_CJSON:= $(wildcard $(ROOT_DIR)/third_party/cJSON/*.c)
OBJS_CJSON:= $(patsubst %.c, %.o, $(SRCS_CJSON))

INC_DIR_SEC:=$(ROOT_DIR)/third_party/bounds_checking_function/include
SRCS_SEC:= $(wildcard $(ROOT_DIR)/third_party/bounds_checking_function/src/*.c)
OBJS_SEC:= $(patsubst %.c, %.o, $(SRCS_SEC))

INC_DIR_HILOG:=  $(ROOT_DIR)/base/hiviewdfx/interfaces/innerkits/hilog \
        $(ROOT_DIR)/base/hiviewdfx/interfaces/innerkits \
        $(ROOT_DIR)/third_party/bounds_checking_function/include 
SRCS_HILOG_C:= $(ROOT_DIR)/base/hiviewdfx/frameworks/hilog_lite/featured/hiview_log.c
SRCS_HILOG_CPP:= $(ROOT_DIR)/base/hiviewdfx/frameworks/hilog_lite/featured/hilog.cpp
OBJS_HILOG_C:= $(patsubst %.c, %.o, $(SRCS_HILOG_C))
OBJS_HILOG_CPP:= $(patsubst %.cpp, %.o, $(SRCS_HILOG_CPP))

INC_DIR_PERMCLIENT:=    $(ROOT_DIR)/base/security/interfaces/kits/iam_lite \
        $(ROOT_DIR)/base/security/services/iam_lite/pms/include \
        $(ROOT_DIR)/base/security/services/iam_lite/pms_base/include \
        $(ROOT_DIR)/utils/native/lite/include \
        $(ROOT_DIR)/foundation/distributedschedule/interfaces/kits/samgr_lite/registry \
        $(ROOT_DIR)/foundation/distributedschedule/interfaces/kits/samgr_lite/samgr \
        $(ROOT_DIR)/foundation/distributedschedule/interfaces/kits/samgr_lite/communication/broadcast \
        $(ROOT_DIR)/foundation/distributedschedule/services/samgr_lite/samgr/source \
        $(ROOT_DIR)/third_party/cJSON \
        $(ROOT_DIR)/third_party/bounds_checking_function/include \
        $(ROOT_DIR)/foundation/communication/interfaces/kits/ipc_lite \
        $(ROOT_DIR)/base/hiviewdfx/interfaces/kits/hilog
SRCS_PERMCLIENT:= $(ROOT_DIR)/base/security/services/iam_lite/pms_client/perm_client.c 
OBJS_PERMCLIENT:= $(patsubst %.c, %.o, $(SRCS_PERMCLIENT))

INC_DIR_SAMGR:= $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/adapter \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/registry \
        $(ROOT_DIR)/foundation/distributedschedule/interfaces/kits/samgr_lite/registry \
        $(ROOT_DIR)/foundation/distributedschedule/interfaces/kits/samgr_lite/samgr \
        $(ROOT_DIR)/utils/native/lite/include \
        $(ROOT_DIR)/kernel/liteos_a/kernel/include/ \
        $(ROOT_DIR)/kernel/liteos_a/kernel/common \
        $(ROOT_DIR)/third_party/bounds_checking_function/include \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr_endpoint/source \
        $(ROOT_DIR)/base/security/services/iam_lite/include \
        $(ROOT_DIR)/base/hiviewdfx/interfaces/kits/hilog \
        $(ROOT_DIR)/foundation/communication/interfaces/kits/ipc_lite \
        $(ROOT_DIR)/base/security/services/iam_lite/ipc_auth/include
SRCS_SAMGR:=    $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/source/samgr_lite.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/source/common.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/source/iunknown.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/source/feature.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/source/service.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/source/message.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/source/task_manager.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/adapter/posix/lock_free_queue.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/adapter/posix/memory_adapter.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/adapter/posix/queue_adapter.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/adapter/posix/thread_adapter.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr/adapter/posix/time_adapter.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr_endpoint/source/client_factory.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr_endpoint/source/default_client.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr_endpoint/source/endpoint.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr_endpoint/source/token_bucket.c \
        $(ROOT_DIR)//foundation/distributedschedule/services/samgr_lite/samgr_client/source/remote_register.c
OBJS_SAMGR:= $(patsubst %.c, %.o, $(SRCS_SAMGR))

INC_DIR_IPC:=   $(ROOT_DIR)/foundation/communication/frameworks/ipc_lite/liteipc/include \
        $(ROOT_DIR)/third_party/bounds_checking_function/include \
        $(ROOT_DIR)/foundation/communication/interfaces/kits/ipc_lite \
        $(ROOT_DIR)/utils/native/lite/include
SRCS_IPC:=      $(ROOT_DIR)/foundation/communication/frameworks/ipc_lite/liteipc/src/liteipc_adapter.c \
        $(ROOT_DIR)/foundation/communication/frameworks/ipc_lite/liteipc/src/serializer.c
OBJS_IPC:= $(patsubst %.c, %.o, $(SRCS_IPC))

LIBS:= 
CC:=gcc
CXX:=g++
CXXFLAGS:= -g -fPIC -Wall -D__LINUX__ $(LIBS) -Wno-deprecated

.PHONY:

all: softbus_lite mbedtls cjson openssl sec_shared hichainsdk_lite huks_lite hilog_lite perm_client samgr_lite ipc_lite
softbus_lite:$(OBJS_SOFTBUS)
mbedtls:$(OBJS_MBEDTLS)
cjson:$(OBJS_CJSON)
sec_shared:$(OBJS_SEC)
hichainsdk_lite:$(OBJS_HICHAINSDK)
huks_lite:$(OBJS_HUKS)
openssl:$(OBJS_OPENSSL)
hilog_lite:$(OBJS_HILOG_C) $(OBJS_HILOG_CPP)
perm_client:$(OBJS_PERMCLIENT)
samgr_lite:$(OBJS_SAMGR)
ipc_lite:$(OBJS_IPC)

$(OBJS_SOFTBUS):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  -DSOFTBUS_DEBUG -D_GNU_SOURCE -D_SCANTY_MEMORY_ $(addprefix -I , $(INC_DIR_SOFTBUS))
	@echo $(CC) -o $@ -c $<
$(OBJS_HUKS):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  -D_FORTIFY_SOURCE=2 $(addprefix -I , $(INC_DIR_HUKS)) -flto -fvisibility=hidden
	@echo $(CC) -o $@ -c $<
$(OBJS_HICHAINSDK):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  -D_CUT_STS_CLIENT_ -D_SCANTY_MEMORY_ -D_CUT_REMOVE_ -D_CUT_ADD_ -D_CUT_LOG_ $(addprefix -I , $(INC_DIR_HICHAINSDK))
	@echo $(CC) -o $@ -c $<
$(OBJS_MBEDTLS):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  $(addprefix -I , $(INC_DIR_MBEDTLS))
	@echo $(CC) -o $@ -c $<
$(OBJS_CJSON):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  $(addprefix -I , $(INC_DIR_CJSON))
	@echo $(CC) -o $@ -c $<
$(OBJS_SEC):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  $(addprefix -I , $(INC_DIR_SEC))
	@echo $(CC) -o $@ -c $<
$(OBJS_OPENSSL):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  $(addprefix -I , $(INC_DIR_OPENSSL))
	@echo $(CC) -o $@ -c $<
$(OBJS_HILOG_C):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  $(addprefix -I , $(INC_DIR_HILOG))
	@echo $(CC) -o $@ -c $<
$(OBJS_HILOG_CPP):%.o:%.cpp
	@$(CXX) $(CXXFLAGS) -o $@ -c $< -DLOSCFG_BASE_CORE_HILOG $(addprefix -I , $(INC_DIR_HILOG))
	@echo $(CXX) -o $@ -c $<
$(OBJS_PERMCLIENT):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  -DLOSCFG_BASE_CORE_HILOG $(addprefix -I , $(INC_DIR_PERMCLIENT))
	@echo $(CC) -o $@ -c $<
$(OBJS_SAMGR):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  -DLITE_LINUX_BINDER_IPC -D_GNU_SOURCE -DSAMGR_LINUX_ADAPTER -DLOSCFG_BASE_CORE_HILOG $(addprefix -I , $(INC_DIR_SAMGR))
	@echo $(CC) -o $@ -c $<
$(OBJS_IPC):%.o:%.c
	@$(CC) $(CXXFLAGS) -o $@ -c $<  $(addprefix -I , $(INC_DIR_IPC)) 
	@echo $(CC) -o $@ -c $<


install:all prepared
	@$(CC) -shared -o $(ROOT_DIR)/out/lib/libsoftbus_lite.so $(OBJS_SOFTBUS) $(OBJS_MBEDTLS) $(OBJS_CJSON) $(OBJS_SEC) \
        $(OBJS_OPENSSL) $(OBJS_HICHAINSDK) $(OBJS_HUKS) $(OBJS_HILOG_C) \
        $(OBJS_HILOG_CPP) $(OBJS_PERMCLIENT) $(OBJS_SAMGR) $(OBJS_IPC) 
	@echo $(CC) -shared -o $(ROOT_DIR)/out/lib/libsoftbus_lite.so OBJS 
	@sudo cp $(ROOT_DIR)/out/lib/* /usr/local/softbus/lib
	@sudo cp -r -n $(INC_DIR) /usr/local/softbus/include
	@echo cp $(ROOT_DIR)/out/lib/* /usr/local/softbus/lib
	@echo cp -r -n INC_DIR /usr/local/softbus/include
	@echo 
	@echo install softbus ... Done!

prepared:
	rm -rf $(ROOT_DIR)/out
	mkdir -p $(ROOT_DIR)/out/lib/
	sudo mkdir -p /usr/local/softbus/lib
	sudo mkdir -p /usr/local/softbus/include

uninstall:
	sudo rm -rf /usr/local/softbus

merge:
	$(CC) -shared -o $(ROOT_DIR)/out/lib/libsoftbus_lite.so $(OBJS_SOFTBUS) $(OBJS_MBEDTLS) $(OBJS_CJSON) $(OBJS_SEC) \
        $(OBJS_OPENSSL) $(OBJS_HICHAINSDK) $(OBJS_HUKS) $(OBJS_HILOG_C) \
        $(OBJS_HILOG_CPP) $(OBJS_PERMCLIENT) $(OBJS_SAMGR) $(OBJS_IPC) 
cp:
	sudo cp $(ROOT_DIR)/out/lib/* /usr/local/softbus/lib/

clean:
	rm -rf $(OBJS_SOFTBUS) $(OBJS_MBEDTLS) $(OBJS_CJSON) $(OBJS_SEC) \
        $(OBJS_OPENSSL) $(OBJS_HICHAINSDK) $(OBJS_HUKS) $(OBJS_HILOG_C) \
        $(OBJS_HILOG_CPP) $(OBJS_PERMCLIENT) $(OBJS_SAMGR) $(OBJS_IPC) \
        $(ROOT_DIR)/out

backup:
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libsoftbus_lite.so $(OBJS_SOFTBUS)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libhichainsdk_lite.so $(OBJS_HICHAINSDK)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libmbedtls_shared.so $(OBJS_MBEDTLS)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libcjson_shared.so $(OBJS_CJSON)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libsec_shared.so $(OBJS_SEC)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libopenssl_shared.so $(OBJS_OPENSSL)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libhuks_lite.so $(OBJS_HUKS)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libhilog_lite.so $(OBJS_HILOG_C) $(OBJS_HILOG_CPP)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libsamgr_lite.so $(OBJS_SAMGR)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libperm_client.so $(OBJS_PERMCLIENT)
	# $(CC) -shared -o $(ROOT_DIR)/out/lib/libipc_lite.so $(OBJS_IPC)
