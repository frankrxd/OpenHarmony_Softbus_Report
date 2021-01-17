<center><font face="黑体" size=6>鸿蒙分布式软总线技术研究</font></center>



[TOC]

### 1、HarmonyOS概述

#### 1.1 系统定义

HarmonyOS 是一款“面向未来”、面向全场景(移动办公、运动健康、社交通 信、媒体娱乐等)的分布式操作系统。在传统的单设备系统能力的基础上，HarmonyOS 提出了基于同一套系统能力、适配多种终端形态的分布式理念，能够支持手机、平板、智能穿戴、智慧屏、车机等多种终端设备。



#### 1.2 系统架构

 HarmonyOS 整体遵从分层设计，从下向上依次为:内核层、系统服务层、框架层和应用层。系统功能按照“系统 > 子系统 > 功能/模块”逐级展开，在多设备部署场景下，支持根据实际需求裁剪某些非必要的子系统或功能/模块。HarmonyOS 技术架构如下所示。

![image-20210117200859231](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6axg51nj31im0u0n5o.jpg)



#### 1.3 分布式技术特性 

HarmonyOS 中，多种设备之间能够实现硬件互助、资源共享，依赖的关键技术 包括分布式软总线、分布式设备虚拟化、分布式数据管理、分布式任务调度等。

![image-20210117200843365](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6aqaahaj31li0ek0v9.jpg)



### 2、分布式软总线模块解析

#### 2.1 分布式软总线的功能

在鸿蒙系统中，分布式软总线是手机、平板、智能穿戴、智慧屏、车机等分布式 设备的通信基座，为设备之间的互联互通提供了统一的分布式通信能力，为设备之 间的无感发现和零等待传输创造了条件。依托软总线技术，可以轻松实现多台设备 共同协作完成一项任务，任务也可以由一台设备传递至另一台设备继续执行。对于用户而言，无需关注多台设备的组网，软总线可以实现自发现、自组网。对于开发 者而言，也无需针对不同设备开发不同版本的软件、适配不同的网络协议和标准规 范。



#### 2.2 分布式软总线的原理 

相较于传统计算机中的硬总线，鸿蒙系统中的分布式软总线是一条虚拟的、“无形”的总线。可以连接同处于一个局域网内部的所有鸿蒙设备(1+8+N，如下图所示)， 并且具有自发现、自组网、高带宽和低时延等特点。

![image-20210117200814365](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6atlgeaj31k00ma78z.jpg)



除了连接处于同样网络协议中的硬件设备，软总线技术还支持对不同协议的异构网络进行组网。传统场景下，需要蓝牙传输的两台设备必须都具有蓝牙，需要 WiFi 传输的设备必须都具有 WiFi。而蓝牙/WiFi 之间是无法进行数据通信的。软总线提出 蓝牙/WiFi 融合网络组网技术(架构如下图所示)，解决了不同协议设备进行数据通 信的问题。使得多个鸿蒙设备能够自动构建一个逻辑全连接网络，用户或者业务开发者无需关心组网方式与物理协议。

![image-20210117200753531](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b3j81zj31ad0u00zo.jpg)



传统协议的传输速率差异较大，多设备交互式时延和可靠性也难以保证。软总线传输提出三个目标:高带宽、低时延、高可靠。相较于传统网络的 7 层模型，软总 线提出了 4 层的“极简协议”(如下图所示)，将中间的 4 层协议精简为一层以提 升有效载荷，有效带宽提升 20%。设备间基于 UDP 协议进行数据传输，摒弃传统滑 动窗口机制，实现丢包快速回复，且具有智能网络变化感知功能，可以自适应流量 控制和拥塞控制。

![image-20210117200935822](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6aydg73j312a0u0n2p.jpg)



#### 2.3 分布式软总线源码结构分析

分布式软中线代码仓库地址如下：

- communication_interfaces_kits_softbuskit_lite

https://gitee.com/openharmony/communication_interfaces_kits_softbuskit_lite

- communication_services_softbus_lite

https://gitee.com/openharmony/communication_services_softbus_lite

顾名思义，分别对应它的接口和实现；而communication_services_softbus_lite源码结构中，又分为authmanager、discovery、trans_service、 和为兼容系统差别而生的os_adapter四大目录。

1. discover:提供基于 COAP 协议的设备发现机制; 
2. authmanager:提供设备认证机制和知识库管理功能; 
3. trans_service:提供身份验证和数据传输通道;
4. os_adapter:检测运行设备性能，决定部分功能是否执行。

![image-20210117201256661](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b0icfsj31lp0u0ahb.jpg)



##### 2.3.1 discover

作为鸿蒙 OS 分布式软总线重要组成单元，discovery 单元提供了基于 coap(Constrained Application Protocol，受限应用协议，RFC7252)协议的设备发现机制。 为什么使用 coap 协议?是因为考虑到运行 harmonyOS 的设备除了硬件性能较好的手 机、电脑等设备，还有资源受限的物联网设备，这些设备的 ram、rom 相对较小。coap 协议支持轻量的可靠传输，采用 coap 协议，可以扩大组网范围。

discovery 的实现前提是确保发现端设备与接收端设备在同一个局域网内且能互 相收到对方的报文。流程为以下三步:

1. 发现端设备，使用 coap 协议在局域网内发送广播;
2. 接收端设备使用 PublishService 接口发布服务，接收端收到广播后，发送 coap 协议单播给发现端;
3. 发现端设备收到回复单播报文,更新设备信息。



discovery 部分代码由两部分组成(目录如下图所示)。其中 coap 部分是 coap 协 议的封装实现, discovery_service 是基于 coap 协议的设备间发现流程的实现。

![image-20210117202121033](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6arez9mj31800u0gtp.jpg)

**coap** 目录中:

1. coap_def.h:定义 coap 协议包的格式、报文结构，且使用 UDP 协议传输; 
2. coap_adapter.c:实现 coap 协议的编码、解码函数; 
3. coap_socket.c:实现 coap 包的发现、接收服务; 
4. Coap_discovery.c:实现基于 coap 协议的设备发现功能。本文件定义了 socket通讯过程 

**discovery_service** 目录中:

1. comman_info_manager.h:定义了鸿蒙系统当前支持的设备类型与级别;
2. Discovery_service.c:实现了设备暴露、发现和连接流程。这里需要注意的 是，考虑到同一局域网下，主设备发出连接请求广播后，多个物联网设备都会回复 单播应答报文从而造成信道冲突。为避免此情况发生，每个物联网设备均维护一套 信号量机制，实现多设备的有序等待。



##### 2.3.2 authmanager

作为软总线代码执行流程中的第二部分:authmanager 单元提供了设备认证机制。设备通过加密和解密的方式，互相建立信任关系，确保在互联场景下，用户数据在 对的设备之间进行流转，实现用户数据的加密传输。软总线中定义加密和解密算法 的内容在 trans_service/utils/aes_gcm.h 中，authmanager 中的处理流程如下图所示:

![image-20210117202542224](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6azad3pj31ie0ion18.jpg)



![image-20210117202612222](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b32g4mj31qa0piq86.jpg)



**authmanager** 目录中:

1. auth_conn.c:提供发送、接收、认证和获取密钥的功能; 
2. auth_interface.c:管理会话、链接、密钥节点，提供增删改查功能;
3. msg_get_deviceid.c:以 cJSON 格式获取各个设备的信息，包括设备 id、链接信息、设备名、设备类型等;
4. bus_manager.c:创建不同的 listen，用以监听系统上有哪些 device 并创建新的 device 节点，以及节点数据的处理。bus_manager.c 主要由 discovery 单元调用， 通过判断本文件中 flag 标志位决定是否启动总线(start_bus()函数)或关闭当前总线 (stop_bus()函数)。discovery 调用后，bus_manager 执行流程如图 10:
5. wifi_auth_manager.c:实现了链接管理和数据接收功能。



![image-20210117202828554](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b23exoj31s20oy77k.jpg)



##### 2.3.3 trans_service 

经过第一阶段协议确定、设备发现，第二阶段设备链接，软总线模块执行到了第三阶段:数据传输阶段，即目录中 trans_service 单元。trans_service 模块依赖于 harmonyOS 提供的网络 socket 服务，向认证模块提供认证通道管理和认证数据的收 发;向业务模块提供 session 管理和基于 session 的数据收发功能，并且通过 GCM 模 块的加密功能提供收发报文的加密/解密保护。如下图所示为 trans_service 模块在系统架构中的位置:

![image-20210117202924463](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b2js49j31ei0kwwht.jpg)



trans_service 目录下源码的结构及其功能如下：

![image-20210117202941456](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6au64j7j31me0u0qa0.jpg)



### 3、编译

#### 3.1 环境

![image-20201231014441938](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b6iyu0j312f0u0gxr.jpg)



#### 3.2 编译过程

配置Makefile

![image-20201231014938382](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6arsx7jj31os0jq0wb.jpg)

![image-20201231015019799](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6aw8442j31dm0u0ako.jpg)



执行编译

![image-20201231014802094](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b7tmkkj31460pek2u.jpg)

make install 后 softbus include目录拷贝到/usr/local/softbus/include  整合依赖打包后的softbus_lite.so拷贝到/usr/local/softbus/lib/ 目录下

![image-20201231020137830](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6ax2p8dj318g0aewht.jpg)



### 4、测试运行

#### 4.1 准备

前面编译生成softbus动态库时需要-g 选项，可以在运行时输出更多的信息

![image-20210101221822038](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6ayslp3j30ym076wfe.jpg)



涉及ipc相关以及部分线程参数设置需要sudo权限，故调试和执行时应在sudo权限下进行。

未在sudo权限下运行出错：

![image-20201231022228200](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6aqw9xij313u09awh2.jpg)



#### 4.2 测试demo

````C
#include <discovery_service.h>
#include <stdio.h>
#include <string.h>
#include <session.h>
#include <tcp_session_manager.h>
#include <nstackx.h>
#include <coap_discover.h>

// 定义业务自身的业务名称，会话名称及相关回调
const char *g_pkgName = "BUSINESS_NAME";
const char *g_sessionName = "SESSION_NAME";
struct ISessionListener * g_sessionCallback= NULL;
#define NAME_LENGTH 64
#define TRANS_FAILED -1
// 回调实现：接收对方通过SendBytes发送的数据，此示例实现是接收到对端发送的数据后回复固定消息
void OnBytesReceivedTest(int sessionId, const void* data, unsigned int dataLen)
{
    printf("OnBytesReceivedTest\n");
    printf("Recv Data: %s\n", (char *)data);
    printf("Recv Data dataLen: %d\n", dataLen);
    char *testSendData = "Hello World, Hello!";
    SendBytes(sessionId, testSendData, strlen(testSendData));
    return;
}
// 回调实现：用于处理会话关闭后的相关业务操作，如释放当前会话相关的业务资源，会话无需业务主动释放
void OnSessionClosedEventTest(int sessionId)
{
    printf("Close session successfully, sessionId=%d\n", sessionId);
}
// 回调实现：用于处理会话打开后的相关业务操作。返回值为0，表示接收；反之，非0表示拒绝。此示例表示只接受其他设备的同名会话连接
int OnSessionOpenedEventTest(int sessionId)
{
    char sessionNameBuffer[NAME_LENGTH+1];
    if(GetPeerSessionName(sessionId,sessionNameBuffer,NAME_LENGTH) == TRANS_FAILED) {
        printf("GetPeerSessionName faild, which sessionId = %d\n",sessionId);
        return -1;
    }
    if (strcmp(sessionNameBuffer,g_sessionName) != 0) {
        printf("Reject the session which name is different from mine, sessionId=%d\n", sessionId);
        return -1;
    }
    printf("Open session successfully, sessionId=%d\n", sessionId);
    return 0;
}
// 向SoftBus注册业务会话服务及其回调
int StartSessionServer()
{
    if (g_sessionCallback == NULL) {
        g_sessionCallback = (struct ISessionListener*)malloc(sizeof(struct ISessionListener));
    }
    if (g_sessionCallback == NULL) {
        printf("Failed to malloc g_sessionCallback!\n");
        return -1;
    }
    g_sessionCallback->onBytesReceived = OnBytesReceivedTest;
    g_sessionCallback->onSessionOpened = OnSessionOpenedEventTest;
    g_sessionCallback->onSessionClosed = OnSessionClosedEventTest;
    int ret = CreateSessionServer(g_pkgName, g_sessionName, g_sessionCallback);
    if (ret < 0) {
        printf("Failed to create session server!\n");
        free(g_sessionCallback);
        g_sessionCallback = NULL;
    }
    return ret;
}
// 从SoftBus中删除业务会话服务及其回调
void StopSessionServer(int x)
{
    int ret = RemoveSessionServer(g_pkgName, g_sessionName);
    if (ret < 0) {
        printf("Failed to remove session server!\n");
        return;
    }
    if (g_sessionCallback != NULL) {
        free(g_sessionCallback);
        g_sessionCallback = NULL;
    }
}

// 服务发布接口使用
void onSuccess(int publishId)
{
    printf("publish succeeded, publishId = %d\r\n", publishId);
    char ipbuff[NSTACKX_MAX_IP_STRING_LEN] = {"0.0.0.0"};
    CoapGetIp(ipbuff,NSTACKX_MAX_IP_STRING_LEN,0);
    printf("CoapGetIp = %s\n",ipbuff);
    if(StartSessionServer()!=-1)
        printf("StartSessionServer successed!\n");
}
void onFail(int publishId, PublishFailReason reason)
{
    printf("publish failed, publishId = %d, reason = %d\r\n", publishId, reason);
}


int main()
{
    PublishInfo info = {0};
    IPublishCallback cb = {0};
    cb.onPublishSuccess = onSuccess;
    cb.onPublishFail = onFail;
    char a[] = "01";
    info.capabilityData = a;
    info.capability = "ddmpCapability";
    info.dataLen = strlen(a);
    info.medium = 2;
    info.publishId = 1;
    PublishService("cxx", &info, &cb);
    sleep(100000);
}
````



#### 4.3 编译运行

编译时需要链接所需库，正确链接动态库需要自行配置动态库路径 LD_LIBRARY_PATH

````
-lsoftbus_lite softbus源码编译生成的动态库
-lrt mqueue相关
-lpthread 线程相关
````

![image-20201231022159081](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b7grxej31390u0n5m.jpg)



### 5、源码分析

#### 5.1 发现机制

用户使用发现功能时，需要保证发现端设备与被发现端设备在同一个局域网内，并且互相能收到对方以下流程的报文。

（1） 发现端设备，发起discover请求后，使用coap协议在局域网内发送广播。报文如下：

![img](https://gitee.com/openharmony/docs/raw/master/readme/figures/1.png)

（2）被发现端设备使用PublishService接口发布服务，接收端收到广播后，发送coap协议单播给发现端。报文格式如下：

![img](https://gitee.com/openharmony/docs/raw/master/readme/figures/2.png)

（3）发现端设备收到报文会更新设备信息。



#### 5.2 PublishService

- SoftBusCheckPermission 权限检查
- SemCreate 信号量
- SemWait  对应SemPost，即PV操作
- **InitService 初始化服务  [重点]**
- AddPublishModule 将PublishInfo结构体内容加入到g_publishModule全局数组
- CoapRegisterDefaultService 注册Coap服务
- PublishCallback 回调Publish结果 对应测试demo里的onSuccess和onFail

![image-20201231022723209](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6h6odwjj30u00zlnbk.jpg)



PublishService执行流程

![image-20210101231211481](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6as8ejoj30hw1aen2a.jpg)

![img](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b4yoy2j310f0iak17.jpg)



InitService执行流程

![img](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6av1vhjj30fp0kmtb7.jpg)



#### 5.3 SoftbusCheckPermission

L0对应非linux版本，仅检查permissionName

````C
int SoftBusCheckPermission(const char* permissionName)
{
    if (permissionName == NULL) {
        return -1;
    }
    return 0;
}
````



L1对应linux版本，检查permissionName后再去调用CheckPermission作进一步的检查

````C
int SoftBusCheckPermission(const char* permissionName)
{
    if (permissionName == NULL) {
        return -1;
    }

    if (CheckPermission(0, permissionName) != GRANTED) {
        SOFTBUS_PRINT("[SOFTBUS] CheckPermission fail\n");
        return -1;
    }
    return 0;
}
````



#### 5.4 SemCreate

​		考虑到同一局域网下，主设备发出连接请求广播后，多个物联网设备都会回复 单播应答报文从而造成信道冲突。为避免此情况发生，每个物联网设备均维护一套 信号量机制，实现多设备的有序等待。

​		SemCreate()在LiteOS中使用了LOS_SemCreate()创建信号量，在Linux上用sem_init()这个Posix标准接口创建信号量。

````C
int SemCreate(unsigned short count, unsigned long *semHandle)
{
    if (semHandle == NULL) {
        return -1;
    }

    (void)count;
    int ret = sem_init((sem_t *)semHandle, 1, 0);
    if (ret == 0) {
        return sem_post((sem_t *)semHandle);
    }
    return ret;
}
````



#### 5.5 InitService

在InitService中

1. 判断是否已经初始化过了，如果是，则直接返回
2. 调用InitCommonManager
3. 为g_publishModule分配空间（保存所有发布服务的模块的信息数组）
4. 为g_capabilityData分配空间
5. 注册wificallback
6. 调用CoapInit 初始化TCPIP协议栈
7. 调用CoapRegisterDeviceInfo
8. 调用BusManager 启动软总线

![image-20210101235502334](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b19wisj30r4154dlh.jpg)



##### InitCommonManager

````c
int InitCommonManager(void)
{
  //调用InitLocalDeviceInfo
    if (InitLocalDeviceInfo() != 0) {
        SOFTBUS_PRINT("[DISCOVERY] InitCommonManager fail\n");
        return ERROR_FAIL;
    }
    return ERROR_SUCCESS;
}
````

````c
int InitLocalDeviceInfo(void)
{
    char deviceId[DEVICEID_MAX_NUM] = {0};
//初始化g_deviceInfo
    if (g_deviceInfo != NULL) {
        memset_s(g_deviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    } else {
        g_deviceInfo = (DeviceInfo *)calloc(1, sizeof(DeviceInfo));
        if (g_deviceInfo == NULL) {
            return ERROR_FAIL;
        }
    }
 /*
 获取IP
 在CoapGetIp中循环调用CoapGetWifiIp来从宏定义的eth或wlan设备中通过调用ioctl函数获取ip地址
 */
#if defined(__LITEOS_A__) || defined(__LINUX__)
    CoapGetIp(g_deviceInfo->deviceIp, NSTACKX_MAX_IP_STRING_LEN, 1);
#endif
    g_deviceInfo->devicePort = -1;
    g_deviceInfo->isAccountTrusted = 1;

/*
获取deviceID
通过函数GetDeviceIdFromFile()调用取得。这个函数会从"/storage/data/softbus/deviceid"文件中读取，如果读取不到，那么使用随机数字符串组成deviceId，然后再写入到上面的文件中。
*/
    unsigned int ret;
    ret = GetDeviceIdFromFile(deviceId, MAX_VALUE_SIZE);
    if (ret != ERROR_SUCCESS) {
        SOFTBUS_PRINT("[DISCOVERY] Get device fail\n");
        return ERROR_FAIL;
    }

  //给g_deviceInfo结构体赋值
#if defined(__LITEOS_M__) || defined(__LITEOS_RISCV__)
    g_deviceInfo->deviceType = L0;
    ret = (unsigned int)strcpy_s(g_deviceInfo->deviceName, sizeof(g_deviceInfo->deviceName), L0_DEVICE_NAME);
#else
    g_deviceInfo->deviceType = L1;
    ret = (unsigned int)strcpy_s(g_deviceInfo->deviceName, sizeof(g_deviceInfo->deviceName), L1_DEVICE_NAME);
#endif

    ret |= (unsigned int)strcpy_s(g_deviceInfo->deviceId, sizeof(g_deviceInfo->deviceId), deviceId);
    ret |= (unsigned int)strcpy_s(g_deviceInfo->version, sizeof(g_deviceInfo->version), "1.0.0");
    if (ret != 0) {
        return ERROR_FAIL;
    }

    SOFTBUS_PRINT("[DISCOVERY] InitLocalDeviceInfo ok\n");
    return ERROR_SUCCESS;
}
````



##### g_publishModule

这个全局变量保存所有发布服务的模块的信息数组，定义如下

````C
typedef struct {
    char package[MAX_PACKAGE_NAME];
    int publishId;
    unsigned short medium;
    unsigned short capabilityBitmap;
    char *capabilityData; //需要分配空间
    unsigned short dataLength;
    unsigned short used;
} PublishModule;
````



##### RegisterWifiCallback

````C
void RegisterWifiCallback(WIFI_PROC_FUNC callback)
{
    g_wifiCallback = callback;
}
````



##### CoapInit

COAP初始化，注册TCP/IP协议栈的处理，注册session的底层socket的处理【重点】

````C
int CoapInit(void)
{
  //调用了NSTACKX_Init 初始化TCPIP协议栈
    int ret = NSTACKX_Init();
    if (ret != 0) {
        SOFTBUS_PRINT("[DISCOVERY] CoapInit NSTACKX_Init fail\n");
        return ERROR_FAIL;
    }
    return ERROR_SUCCESS;
}
````

查看NSTACKX_Init的代码

````C
int NSTACKX_Init()
{
    int ret;
  //判断g_nstackInitState是否为NSTACKX_INIT_STATE_START
    if (g_nstackInitState != NSTACKX_INIT_STATE_START) {
        return NSTACKX_EOK;
    }
	//将g_nstackInitState置为ONGOING状态
    g_nstackInitState = NSTACKX_INIT_STATE_ONGOING;
    cJSON_InitHooks(NULL);

  //调用CoapInitDiscovery
    ret = CoapInitDiscovery();
    if (ret != NSTACKX_EOK) {
        goto L_ERR_INIT;
    }
    g_nstackInitState = NSTACKX_INIT_STATE_DONE;
    return NSTACKX_EOK;

L_ERR_INIT:
    ret = NSTACKX_Deinit();
    if (ret != NSTACKX_EOK) {
        SOFTBUS_PRINT("[DISCOVERY] deinit fail\n");
    }
    return NSTACKX_EFAILED;
}
````

继续查看CoapInitDiscovery的代码

````C

int CoapInitDiscovery(void)
{
  //调用CoapInitSocket初始化Socket
    int ret = CoapInitSocket();
    if (ret != NSTACKX_EOK) {
        SOFTBUS_PRINT("[DISCOVERY] Init socket fail\n");
        return ret;
    }
#if defined(__LITEOS_M__) || defined(__LITEOS_RISCV__)
    int rtn = CoapInitWifiEvent();
    if (rtn != NSTACKX_EOK) {
        SOFTBUS_PRINT("[DISCOVERY] Init wifi event fail\n");
        return rtn;
    }
#endif
  //调用CreateCoapListenThread 创建监听线程
    return CreateCoapListenThread();
}
````

查看CoapInitSocket

````C
int CoapInitSocket(void)
{
  //判断是否已经初始化过g_serverFd了
    if (g_serverFd >= 0) {
        return NSTACKX_EOK;
    }
  //初始化sockaddr_in
    struct sockaddr_in sockAddr;
    (void)memset_s(&sockAddr, sizeof(sockAddr), 0, sizeof(sockAddr));
    sockAddr.sin_port = htons(COAP_DEFAULT_PORT);
  //调用CoapCreateUdpServer来创建UDP socket并bind，COAP_DEFAULT_PORT（5684）端口，返回sockFd
    g_serverFd = CoapCreateUdpServer(&sockAddr);
    if (g_serverFd < 0) {
        return NSTACKX_OVERFLOW;
    }
  
  //初始化g_msgId
    COAP_SoftBusInitMsgId();
    return NSTACKX_EOK;
}
````

查看CreateCoapListenThread

````C
int CreateCoapListenThread(void)
{
    g_terminalFlag = 1;
    if (g_coapTaskId != -1) {
        return NSTACKX_EOK;
    }

  //设置线程相关参数
  /*
struct ThreadAttr {
    const char *name;
    uint32_t stackSize;
    uint8_t priority;
    uint8_t reserved1;
    uint16_t reserved2;
};
*/
    ThreadAttr attr = {"coap_listen_task", 0x800, 20, 0, 0};
  
  //创建线程，线程中执行CoapReadHandle
    int error = CreateThread((Runnable)CoapReadHandle, NULL, &attr, (unsigned int*)&g_coapTaskId);
    if (error != 0) {
        g_terminalFlag = 0;
        SOFTBUS_PRINT("[DISCOVERY] create task fail\n");
        return NSTACKX_EFAILED;
    }
  
    return NSTACKX_EOK;
}
````

查看CreateThread

````C
int CreateThread(Runnable run, void *argv, const ThreadAttr *attr, unsigned int *threadId)
{
    pthread_attr_t threadAttr; //线程属性
    pthread_attr_init(&threadAttr);//init
    pthread_attr_setstacksize(&threadAttr, (attr->stackSize | MIN_STACK_SIZE));
    struct sched_param sched = {attr->priority};//线程优先级
    pthread_attr_setschedparam(&threadAttr, &sched); //设置线程优先级
    int errCode = pthread_create((pthread_t *)threadId, &threadAttr, run, argv); //创建线程，run为传入的CoapReadHandle函数指针
    return errCode;
}
````

查看CoapReadHandle

````C
static void CoapReadHandle(unsigned int uwParam1, unsigned int uwParam2, unsigned int uwParam3, unsigned int uwParam4)
{
    (void)uwParam1;
    (void)uwParam2;
    (void)uwParam3;
    (void)uwParam4;
    int ret;
    fd_set readSet;
    int serverFd = GetCoapServerSocket();//获取serverFd
    SOFTBUS_PRINT("[DISCOVERY] CoapReadHandle coin select begin\n");
  
  /*
  使用了io多路复用的select, 对于io多路复用还有改进版的poll和epoll
  */
    while (g_terminalFlag) {
      //select维护了一个bitset，每轮循环要先都设置为0
        FD_ZERO(&readSet);
      //将serverFd加入select监听集合中
        FD_SET(serverFd, &readSet);
      //select函数 成功时返回事件的个数 
        ret = select(serverFd + 1, &readSet, NULL, NULL, NULL);//timeval设置为Null时会阻塞等待，直到有描述符准备好IO后才返回
        if (ret > 0) {
            if (FD_ISSET(serverFd, &readSet)) { //判断serverFd是否可读
                HandleReadEvent(serverFd);//处理IO事件
            }
        } else {
            SOFTBUS_PRINT("[DISCOVERY]ret:%d,error:%d\n", ret, errno);
        }
    }
    SOFTBUS_PRINT("[DISCOVERY] CoapReadHandle exit\n");
}
````

继续查看HandleReadEvent

````C
static void HandleReadEvent(int fd)
{
    int socketFd = fd;
    unsigned char *recvBuffer = calloc(1, COAP_MAX_PDU_SIZE + 1);
    if (recvBuffer == NULL) {
        return;
    }
    ssize_t nRead;
  //调用CoapSocketRecv来接收数据，读入recvBuffer中
    nRead = CoapSocketRecv(socketFd, recvBuffer, COAP_MAX_PDU_SIZE);
    if ((nRead == 0) || (nRead < 0 && errno != EAGAIN &&
        errno != EWOULDBLOCK && errno != EINTR)) {
        free(recvBuffer);
        return;
    }
  
    COAP_Packet decodePacket;
    (void)memset_s(&decodePacket, sizeof(COAP_Packet), 0, sizeof(COAP_Packet));
    decodePacket.protocol = COAP_UDP;
  //调用COAP_SoftBusDecode()函数对COAP协议进行解析，解析的内容放在decodePacket结构中
    COAP_SoftBusDecode(&decodePacket, recvBuffer, nRead);
  //最后调用PostServiceDiscover()发现端设备发送的DISCOVER消息进行回应
    PostServiceDiscover(&decodePacket);
    free(recvBuffer);
}
````

继续查看PostServiceDiscover

````C
void PostServiceDiscover(COAP_Packet *pkt)
{
    char *remoteUrl = NULL;
    DeviceInfo deviceInfo;

    if (pkt == NULL) {
        return;
    }
 //获取deviceInfo
    (void)memset_s(&deviceInfo, sizeof(deviceInfo), 0, sizeof(deviceInfo));
    if (GetServiceDiscoverInfo(pkt->payload.buffer, pkt->payload.len, &deviceInfo, &remoteUrl) != NSTACKX_EOK) {
        return;
    }
 //获取wifiIpAddr
    char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    (void)memset_s(wifiIpAddr, sizeof(wifiIpAddr), 0, sizeof(wifiIpAddr));
    (void)inet_ntop(AF_INET, &deviceInfo.netChannelInfo.wifiApInfo.ip, wifiIpAddr, sizeof(wifiIpAddr));

    if (remoteUrl != NULL) {
      //调用CoapResponseService
        CoapResponseService(pkt, remoteUrl, wifiIpAddr);
        free(remoteUrl);
    }
}
````

继续查看CoapResponseService

````C
static int CoapResponseService(const COAP_Packet *pkt, const char* remoteUrl, const char* remoteIp)
{
    int ret;
    CoapRequest coapRequest;
    (void)memset_s(&coapRequest, sizeof(coapRequest), 0, sizeof(coapRequest));
    coapRequest.remoteUrl = remoteUrl;
    coapRequest.remoteIp = remoteIp;
    char *payload = PrepareServiceDiscover();
    if (payload == NULL) {
        return NSTACKX_EFAILED;
    }

    COAP_ReadWriteBuffer sndPktBuff = {0};
    sndPktBuff.readWriteBuf = calloc(1, COAP_MAX_PDU_SIZE);
    if (sndPktBuff.readWriteBuf == NULL) {
        free(payload);
        return NSTACKX_EFAILED;
    }
    sndPktBuff.size = COAP_MAX_PDU_SIZE;
    sndPktBuff.len = 0;

    ret = BuildSendPkt(pkt, remoteIp, payload, &sndPktBuff);
    free(payload);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        free(sndPktBuff.readWriteBuf);
        sndPktBuff.readWriteBuf = NULL;
        return ret;
    }
    coapRequest.data = sndPktBuff.readWriteBuf;
    coapRequest.dataLength = sndPktBuff.len;
  
  //在这之前是发送前准备，调用CoapSendRequest
    ret = CoapSendRequest(&coapRequest);
    free(sndPktBuff.readWriteBuf);
    sndPktBuff.readWriteBuf = NULL;

    return ret;
}
````

继续查看CoapSendRequest

````C
static int CoapSendRequest(const CoapRequest *coapRequest)
{
    if (coapRequest == NULL || coapRequest->remoteUrl == NULL) {
        return NSTACKX_EFAILED;
    }

    struct sockaddr_in sockAddr = {0};
    if (coapRequest->remoteIp == NULL) {
        return NSTACKX_EFAILED;
    }

    sockAddr.sin_addr.s_addr = inet_addr(coapRequest->remoteIp);
    sockAddr.sin_port = htons(COAP_DEFAULT_PORT);
    sockAddr.sin_family = AF_INET;

    int ret = CoapCreatUdpClient(&sockAddr);
    if (ret != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    SocketInfo socket = {0};
    socket.cliendFd = GetCoapClientSocket();
    socket.dstAddr = sockAddr;
  //定位到CoapSocketSend CoapSocketSend最终调用sendto进行数据发送
    if (CoapSocketSend(&socket, (uint8_t *)coapRequest->data, coapRequest->dataLength) == -1) {
        SOFTBUS_PRINT("[DISCOVERY]reponse coap failed.\r\n");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
````



##### CoapRegisterDeviceInfo

注册设备信息

````C
int CoapRegisterDeviceInfo(void)
{
    NSTACKX_LocalDeviceInfo localDeviceInfo;
    int ret;

    (void)memset_s(&localDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo), 0, sizeof(NSTACKX_LocalDeviceInfo));
  //获取localDeviceInfo
  /*
  typedef struct {
    char name[NSTACKX_MAX_DEVICE_NAME_LEN];
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    char btMacAddr[NSTACKX_MAX_MAC_STRING_LEN];
    char wifiMacAddr[NSTACKX_MAX_MAC_STRING_LEN];
    char networkIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    uint8_t is5GHzBandSupported;
    int deviceType;
    char version[NSTACKX_MAX_HICOM_VERSION];
} NSTACKX_LocalDeviceInfo;
  */
    ret = CoapGetLocalDeviceInfo(&localDeviceInfo);
    if (ret != 0) {
        return ERROR_FAIL;
    }

  //注册设备信息
    ret = NSTACKX_RegisterDeviceAn(&localDeviceInfo, DEV_HASH_ID);
    if (ret != 0) {
        SOFTBUS_PRINT("[DISCOVERY] CoapRegisterDeviceInfo RegisterDeviceAn fail\n");
        return ERROR_FAIL;
    }

    return ERROR_SUCCESS;
}
````



##### BusManage

````C
int BusManager(unsigned int startFlag)
{
    if (startFlag == 1) {
        return StartBus();
    } else {
        return StopBus();
    }
}
````

继续查看StartBus

````C
int StartBus(void)
{
    if (g_busStartFlag == 1) {
        return 0;
    }
    DeviceInfo *info = GetCommonDeviceInfo();
    if (info == NULL) {
        return ERROR_FAIL;
    }
	//OnConnectEvent()函数中完成对新连接的处理, OnDataEvent()函数中完成对新数据的处理。
    g_baseLister.onConnectEvent = OnConnectEvent;
    g_baseLister.onDataEvent = OnDataEvent;
  
  //StartListener()函数负责为认证模块提供通道完成初始化
    int authPort = StartListener(&g_baseLister, info->deviceIp);
    if (authPort < 0) {
        SOFTBUS_PRINT("[AUTH] StartBus StartListener fail\n");
        return ERROR_FAIL;
    }
    info->devicePort = authPort;

  //StartSession()函数负责初始化业务的session管理
    int sessionPort = StartSession(info->deviceIp);
    if (sessionPort < 0) {
        SOFTBUS_PRINT("[AUTH] StartBus StartSession fail\n");
        StopListener();
        return ERROR_FAIL;
    }

    AuthMngInit(authPort, sessionPort);
    g_busStartFlag = 1;

    SOFTBUS_PRINT("[AUTH] StartBus ok\n");
    return 0;
}
````

继续查看StartListener

````C
int StartListener(BaseListener *callback, const char *ip)
{
    if (callback == NULL || ip == NULL) {
        return -DBE_BAD_PARAM;
    }

    g_callback = callback;

    //StartListener()调用InitListenFd()函数完成监听TCP socket的创建和监听
    int rc = InitListenFd(ip, SESSIONPORT);
    if (rc != DBE_SUCCESS) {
        return -DBE_BAD_PARAM;
    }

    signal(SIGPIPE, SIG_IGN);
    ThreadAttr attr = {"auth", 0x800, 20, 0, 0};
  
  //Linux下 AuthCreate()会调用POSIX的pthread_create()完成线程的创建，线程的入口函数为static void WaitProcess(void)
    register ThreadId threadId = (ThreadId)AuthCreate((Runnable)WaitProcess, &attr);
    if (threadId == NULL) {
        SOFTBUS_PRINT("[TRANS] StartListener AuthCreate fail\n");
        return -1;
    }
    return GetSockPort(g_listenFd);
}
````

继续查看WaitProcess

````C
static void WaitProcess(void)
{
    SOFTBUS_PRINT("[TRANS] WaitProcess begin\n");
    fd_set readSet;
    fd_set exceptfds;

    while (1) {
        //与CoapInit中CoapReadHandle类似，同样使用io多路复用的select来实现对io事件的处理
        FD_ZERO(&readSet);
        FD_ZERO(&exceptfds);
        FD_SET(g_listenFd, &readSet);
        if (g_dataFd >= 0) {
            FD_SET(g_dataFd, &readSet);
            FD_SET(g_dataFd, &exceptfds);
        }
        int ret = select(g_maxFd + 1, &readSet, NULL, &exceptfds, NULL);
        if (ret > 0) {
          /*WaitProcess()使用忙等方式，调用select()来监听listenFd和数据g_dataFd的信息，如果监听到有数据可读，则进入ProcessAuthData来处理。
          无论是新连接请求，还是已有连接中有数据到来，均会进入ProcessAuthData
          函数通过FD_ISSET()判断是否是listenFd上存在消息,是的话说明有新连接，则调用onConnectEvent来处理新到来的连接请求，并将新创建的fd和client的IP地址告知认证模块。与此同时，创建g_dataFd时候需要刷新g_maxFd，以保证在WaitProcess()中的下一次select()操作时中，会监听到g_dataFd上的事件
          如果FD_ISSET()判断出g_dataFd上存在消息，则说明已完成握手的连接向本节点发送了数据，这时函数回调onDataEvent，以处理接收到的数据
          */
            if (!ProcessAuthData(g_listenFd, &readSet)) {
                SOFTBUS_PRINT("[TRANS] WaitProcess ProcessAuthData fail\n");
                StopListener();
                break;
            }
        } else if (ret < 0) {
          //如果发现g_dataFd有异常信息，则将其关闭。其中g_dataFd是由listenFd监听到连接时创建的socket
            if (errno == EINTR || (g_dataFd > 0 && FD_ISSET(g_dataFd, &exceptfds))) {
                SOFTBUS_PRINT("[TRANS] errno == EINTR or g_dataFd is in exceptfds set.\n");
                CloseAuthSessionFd(g_dataFd);
                continue;
            }
            SOFTBUS_PRINT("[TRANS] WaitProcess select fail, stop listener\n");
            StopListener();
            break;
        }
    }
}
````



查看StartSession

````C
int StartSession(const char *ip)
{
    int port = CreateTcpSessionMgr(true, ip);
    return port;
}
````

继续查看CreateTcpSessionMgr

````C
int CreateTcpSessionMgr(bool asServer, const char* localIp)
{
    if (g_sessionMgr != NULL || localIp == NULL) {
        return TRANS_FAILED;
    }
  //初始化g_sessionMgr
    g_sessionMgr = malloc(sizeof(TcpSessionMgr));
    if (g_sessionMgr == NULL) {
        return TRANS_FAILED;
    }
    (void)memset_s(g_sessionMgr, sizeof(TcpSessionMgr), 0, sizeof(TcpSessionMgr));
    g_sessionMgr->asServer = asServer;
    g_sessionMgr->listenFd = -1;
    g_sessionMgr->isSelectLoopRunning = false;

    if (InitTcpMgrLock() != 0 || GetTcpMgrLock() != 0) {
        FreeSessionMgr();
        return TRANS_FAILED;
    }

    for (int i = 0; i < MAX_SESSION_SUM_NUM; i++) {
        g_sessionMgr->sessionMap_[i] = NULL;
    }

    for (int i = 0; i < MAX_SESSION_SERVER_NUM; i++) {
        g_sessionMgr->serverListenerMap[i] = NULL;
    }

    if (ReleaseTcpMgrLock() != 0) {
        FreeSessionMgr();
        return TRANS_FAILED;
    }
	//创建OpenTcpServer完成了socket的创建和bind，返回listenFd
    int listenFd = OpenTcpServer(localIp, DEFAULT_TRANS_PORT);
    if (listenFd < 0) {
        SOFTBUS_PRINT("[TRANS] CreateTcpSessionMgr OpenTcpServer fail\n");
        FreeSessionMgr();
        return TRANS_FAILED;
    }
  //listen，返回sessionId
    int rc = listen(listenFd, LISTEN_BACKLOG);
    if (rc != 0) {
        SOFTBUS_PRINT("[TRANS] CreateTcpSessionMgr listen fail\n");
        CloseSession(listenFd);
        FreeSessionMgr();
        return TRANS_FAILED;
    }
    g_sessionMgr->listenFd = listenFd;

    signal(SIGPIPE, SIG_IGN);
  //StartSelectLoop
    if (StartSelectLoop(g_sessionMgr) != 0) {
        SOFTBUS_PRINT("[TRANS] CreateTcpSessionMgr StartSelectLoop fail\n");
        CloseSession(listenFd);
        FreeSessionMgr();
        return TRANS_FAILED;
    }
    return GetSockPort(listenFd);
}
````

继续查看StartSelectLoop

````C
int StartSelectLoop(TcpSessionMgr *tsm)
{
    if (tsm == NULL) {
        return TRANS_FAILED;
    }
    if (tsm->isSelectLoopRunning) {
        return 0;
    }
    ThreadAttr attr = {"tcp", 0x800, 20, 0, 0};
    register ThreadId threadId = (ThreadId)TcpCreate((Runnable)SelectSessionLoop, tsm, &attr);
    if (threadId == NULL) {
        return TRANS_FAILED;
    }
    tsm->isSelectLoopRunning = true;
    return 0;
}

//同样是用select实现
static void SelectSessionLoop(TcpSessionMgr *tsm)
{
    if (tsm == NULL) {
        return;
    }
    SOFTBUS_PRINT("[TRANS] SelectSessionLoop begin\n");
    tsm->isSelectLoopRunning = true;
    while (true) {
        fd_set readfds;
        fd_set exceptfds;
        int maxFd = InitSelectList(tsm, &readfds, &exceptfds);
        if (maxFd < 0) {
            break;
        }

        errno = 0;
        int ret = select(maxFd + 1, &readfds, NULL, &exceptfds, NULL);
        if (ret < 0) {
            SOFTBUS_PRINT("RemoveExceptSessionFd\r\n");
            if (errno == EINTR || RemoveExceptSessionFd(tsm, &exceptfds) == 0) {
                continue;
            }
            SOFTBUS_PRINT("[TRANS] SelectSessionLoop close all Session\n");
            CloseAllSession(tsm);
            break;
        } else if (ret == 0) {
            continue;
        } else {
          //对事件的处理
            ProcessData(tsm, &readfds);
        }
    }
    tsm->isSelectLoopRunning = false;
}
````



#### 5.6 AddPublishModule

AddPublishModule()函数，将把moduleName和info（PublishInfo结构）中的内容加入到g_publishModule全局数组中

````C
PublishModule *AddPublishModule(const char *packageName, const PublishInfo *info)
{
    if (packageName == NULL || g_publishModule == NULL || info == NULL) {
        return NULL;
    }

    if (info->dataLen > MAX_SERVICE_DATA_LEN) {
        return NULL;
    }

    if (FindExistModule(packageName, info->publishId) != NULL) {
        return NULL;
    }

    if (FindFreeModule() == NULL) {
        return NULL;
    }
    int ret;
    for (int i = 0; i < MAX_MODULE_COUNT; i++) {
        if (g_publishModule[i].used == 1) {
            continue;
        }

        if (ParseCapability(info->capability, &g_publishModule[i].capabilityBitmap)) {
            return NULL;
        }

        g_publishModule[i].used = 1;
        g_publishModule[i].capabilityData = calloc(1, info->dataLen + 1);
        if (g_publishModule[i].capabilityData == NULL) {
            memset_s(&g_publishModule[i], sizeof(g_publishModule[i]), 0, sizeof(g_publishModule[i]));
            return NULL;
        }
        g_publishModule[i].dataLength = info->dataLen + 1;
        ret = memcpy_s(g_publishModule[i].capabilityData,
                       g_publishModule[i].dataLength,
                       info->capabilityData, info->dataLen);
        if (ret != 0) {
            free(g_publishModule[i].capabilityData);
            g_publishModule[i].capabilityData = NULL;
            memset_s(&g_publishModule[i], sizeof(g_publishModule[i]), 0, sizeof(g_publishModule[i]));
            return NULL;
        }
        g_publishModule[i].medium = info->medium;
        g_publishModule[i].publishId = info->publishId;
        ret = memcpy_s(g_publishModule[i].package, MAX_PACKAGE_NAME, packageName, strlen(packageName));
        if (ret != 0) {
            free(g_publishModule[i].capabilityData);
            g_publishModule[i].capabilityData = NULL;
            memset_s(&g_publishModule[i], sizeof(g_publishModule[i]), 0, sizeof(g_publishModule[i]));
            return NULL;
        }
        return &g_publishModule[i];
    }
    return NULL;
}
````



#### 5.7 CoapRegisterDefaultService

````C
int CoapRegisterDefualtService(void)
{
    DeviceInfo *info = GetCommonDeviceInfo();
    if (info == NULL) {
        return ERROR_FAIL;
    }

    char serviceData[MAX_DEFAULT_SERVICE_DATA_LEN] = {0};
 // 代码中的 info->devicePort 就是基于TCP的认证服务的socket绑定的端口号（在StartBus()函数中赋值的）。而serviceData就是 “port:%d”的子串
    if (sprintf_s(serviceData, sizeof(serviceData), "port:%d", info->devicePort) == -1) {
        return ERROR_FAIL;
    }

    return NSTACKX_RegisterServiceData(serviceData);
}

//把g_localDeviceInfo.serverData赋值成 “port:auth_port”这样的子串
int NSTACKX_RegisterServiceData(const char* serviceData)
{
    if (serviceData == NULL) {
        return NSTACKX_EINVAL;
    }

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        return NSTACKX_EFAILED;
    }
    unsigned int serviceLen = strlen(serviceData);
    if (serviceLen >= NSTACKX_MAX_SERVICE_DATA_LEN) {
        return NSTACKX_EINVAL;
    }

    if (RegisterServiceData(serviceData, serviceLen + 1) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int RegisterServiceData(const char* serviceData, int length)
{
    if (serviceData == NULL) {
        return NSTACKX_EINVAL;
    }

    (void)memset_s(g_localDeviceInfo.serviceData, sizeof(g_localDeviceInfo.serviceData),
        0, sizeof(g_localDeviceInfo.serviceData));
    if (strcpy_s(g_localDeviceInfo.serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, serviceData) != EOK)  {
        return NSTACKX_EFAILED;
    }

    (void)length;
    return NSTACKX_EOK;
}
````



### 6、编译和调试过程中遇到的问题

#### 6.1 uint16_t unknown type

![image-20210102025115778](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6avjkzxj314e0ae78h.jpg)

解决：

在tcp_socket.h中加上

````C
typedef unsigned short uint16_t;
````

或者用第三方musl-gcc编译



#### 6.2 CoapGetIp获取IP地址失败的问题

Coap底层调用ioctl获取ip地址

解决：

ipconfig查看网络设备和地址

![image-20210102032821776](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6asskrxj314a0gudlh.jpg)

discovery/coap/source/coap_discover.c中修改宏定义

![image-20210102033008754](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b450i3j30go02yaa9.jpg)



#### 6.3 sem_init 在linux semaphore实现中越界读写的问题

在调试过程中发现在linux下会有异常修改lisenFD的现象。原因在于在discovery_service.c中将g_serviceSemID定义为一个unsigned long类型，在后面强制类型转换为sem_t，对应sem_t的结构体。在linux下的posix semaphore实现的信号量中访问了越界的地址区域，导致了listenFd被异常修改。



代码的g_serviceSemId定义 后面被强制类型转换为信号量sem_t

![image-20210101233700628](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6aqi97zj30je03cjrr.jpg)

linux下的posix标准semaphore中关于信号量sem_t的定义

<img src="https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b5hf9bj30ls08yt9h.jpg" alt="image-20210101234601883" style="zoom:50%;" />

由于listenFd被异常修改导致InitService BusManager出错

![image-20210102021742794](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b5yptjj30x20acq5t.jpg)

gdb调试

![image-20210102021955948](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6azv9xzj31460j8td2.jpg)



解决方法是为g_serviceSemId开辟与sem_t同样大小的静态变量空间

````C
static unsigned long g_serviceSemId[sizeof(sem_t)/sizeof(long)]= {INVALID_SEM_ID};
````



#### 6.4 在linux下多线程创建中遇到的问题

代码路径trans_service/source/libdistbus/tcp_session_manager.c

````C
//源代码实现
ThreadId TcpCreate(Runnable run, void *argv, const ThreadAttr *attr)
{
    if (attr == NULL) {
        return NULL;
    }
    int ret;
    pthread_attr_t threadAttr;

    ret = pthread_attr_init(&threadAttr);
    if (ret != 0) {
        return NULL;
    }
    ret = pthread_attr_setstacksize(&threadAttr, (attr->stackSize | MIN_STACK_SIZE));
    if (ret != 0) {
        return NULL;
    }

    struct sched_param sched = {attr->priority};

    ret = pthread_attr_setschedparam(&threadAttr, &sched); //
    if (ret != 0) {
        return NULL;
    }
  
    pthread_t threadId = 0;
    ret = pthread_create(&threadId, &threadAttr, run, argv);
    if (ret != 0) {
        return NULL;
    }
    if (attr->name != NULL) {
        ret = pthread_setname_np(threadId, attr->name);
        if (ret != 0) {
            SOFTBUS_PRINT("[TRANS] TcpCreate setname fail\n");
        }
    }

    return (ThreadId)threadId;
}
````

执行出错

![image-20210102023408441](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6axuse2j30wi0c6q6g.jpg)



gdb调试，是位于TcpCreate/pthread_attr_setschedparam 设置线程优先级时失败导致错误

![image-20210102023553822](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b4l6ljj31460rggs7.jpg)

查看函数栈

![image-20210102023801590](https://tva1.sinaimg.cn/large/008eGmZEgy1gmr6b1ocs2j313o0ta13u.jpg)



解决方法

````C
//在设置优先级前
//必需设置inher的属性为 PTHREAD_EXPLICIT_SCHED，否则设置线程的优先级会被忽略  
ret = pthread_attr_setinheritsched(&threadAttr,PTHREAD_EXPLICIT_SCHED);
if (ret != 0) {
  return NULL;
}
//设置线程调度策略  
/*
linux内核的三种调度方法：
1，SCHED_OTHER 分时调度策略，
2，SCHED_FIFO实时调度策略，先到先服务
3，SCHED_RR实时调度策略，时间片轮转
*/
ret = pthread_attr_setschedpolicy(&threadAttr,SCHED_RR); //需要在sudo权限下
if (ret != 0) {
  return NULL;
}
//设置线程优先级
struct sched_param sched = {attr->priority};
ret = pthread_attr_setschedparam(&threadAttr, &sched);
if (ret != 0) {
  return NULL;
}
````



或者采用third_party/musl的第三方线程库进行源码编译 用musl-gcc编译



### 7、参考

软总线调研报告-朱浩-SA20225646

[编译构建子系统README](https://gitee.com/openharmony/docs/blob/master/readme/编译构建子系统README.md)

[分布式通信子系统README](https://gitee.com/openharmony/docs/blob/master/readme/分布式通信子系统README.md)

[鸿蒙子系统解读-分布式软总线子系统初步研究](https://blog.csdn.net/weixin_47070198/article/details/109842610)

