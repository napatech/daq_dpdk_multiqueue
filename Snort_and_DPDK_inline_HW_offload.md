## Snort Hardware offload for Project Diamond Back
When running inline/IPS every packet/flow handed to Snort is classified according to the rule’s setup. Snort has the following classification:



| Classification         | Description                                                                            |
|------------------------|----------------------------------------------------------------------------------------|
| DAQ_VERDICT_PASS       | Pass the packet                                                                        | 
| DAQ_VERDICT_BLOCK      | Block the packet                                                                       |   
| DAQ_VERDICT_REPLACE    | Pass a packet that has been modified in-place. (No resizing allowed!)                  |
| DAQ_VERDICT_WHITELIST  | Pass the packet and fast path all future packets in the same flow systemwide.           |
| DAQ_VERDICT_BLACKLIST  | Block the packet and block all future packets in the same flow systemwide.             |
| DAQ_VERDICT_IGNORE     | Pass the packet and fast path all future packets in the same flow for this application. |
| DAQ_VERDICT_RETRY      | Hold the packet briefly and resend it to Snort while Snort waits for external response.<br>Drop any new packets received on that flow while holding before sending them to Snort.               |
  
In a hardware offload perspective, the interesting classifications are:

- DAQ_VERDICT_WHITELIST 
- DAQ_VERDICT_BLACKLIST
- DAQ_VERDICT_IGNORE

##### DAQ_VERDICT_WHITELIST
Snort has identified the flow as harmless or not dangerous. In fact Snort does not want to see anymore packets from this flow, which means that all packets contained by this flow can be fast pathed. In other terms it means that it is possible for the adapter to forward all remaining packets contained by the flow by using local retransmit filter.
   
##### DAQ_VERDICT_BLACKLIST
Snort has identified the flow as dangerous. In fact Snort does not want to see anymore packets from this flow either, which means that all packets contained by this flow must be blocked. In other terms it means that it is possible for the adapter to block all packets contained by the flow by using a drop filter. 

##### DAQ_VERDICT_IGNORE
This classification has the same meaning as DAQ_VERDICT_WHITELIST and is handled in the same way.


## Napatech SmartNics
All Napatech SmartNics supported by DPDK will be able to do HW offload when using Snort, but as the SmartNics is using NTPL (KeyMatcher) to program the local retransmit and the drop filters it will be fairly slow and not very usable. 

### Diamond Back SmartNic
A new SmartNic/FPGA has been made supporting a FlowMatcher. The FlowMatcher uses a much simpler programming in order to program the filters and it is much more faster.

To setup a retransmit and drop filter first some basis NTPL filters must be setup. This has only to be done once as the NTPL filters will be reused by all following FlowMatcher programming.

##### General NTPL Filters
First some generic filters has to be setup in order to receive and classify packet types.

```
assign[priority=10;Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0];streamid=0;colormask=0x1;tag=port0]= port==0

assign[priority=10;Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0];streamid=0;colormask=0x11;tag=port0]=(Layer3Protocol==IPV4) and port==0

assign[priority=10;Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0];streamid=0;colormask=0x41;tag=port0]=(Layer3Protocol==IPV6) and port==0

assign[priority=10;Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0];streamid=0;colormask=0x201;tag=port0]=(Layer4Protocol==UDP) and port==0

assign[priority=10;Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0];streamid=0;colormask=0x101;tag=port0]=(Layer4Protocol==TCP) and port==0

assign[priority=10;Descriptor=DYN3,length=24,colorbits=32,Offset0=Layer3Header[0],Offset1=Layer4Header[0];streamid=0;colormask=0x401;tag=port0]=(Layer4Protocol==SCTP) and port==0
```
Note that the colormask used to mark the received packets are the same masks used by DPDK to classify packets. In that way it is possible to copy the colormask directly to DPDKs mbuf packet type without any further handling.

| Color mask | Packet type | DPDK packet type |
|------------|-------------|------------------| 
| 0x001      | Ethernet    |RTE_PTYPE_L2_ETHER|
| 0x010      | IPv4        |RTE_PTYPE_L3_IPV4 |
| 0x040      | IPv6        |RTE_PTYPE_L3_IPV6 |
| 0x100      | TCP         |RTE_PTYPE_L4_TCP  |
| 0x200      | UDP         |RTE_PTYPE_L4_UDP  |
| 0x400      | SCTP        |RTE_PTYPE_L4_SCTP |

The LAYER3 and LAYER4 offset is also copied directly to the DPDK mbuf without any further handling.

##### Flow matcher NTPL filters
For the flow matcher to work, some specific NTPL filters must be setup too. 

When the first packet is received both a retransmit filter and a drop filer will be created for both IPv4 and IPv6.
###### IPv4 filters:
```
KeyType[name=KT2;Access=partial;Bank=0;KeyID=2;tag=port1]={32,32,16,16}
KeyDef[name=KDEF2;KeyType=KT2;prot=OUTER;tag=port1]=(Layer3Header[12]/32,Layer3Header[16]/32,Layer4Header[0]/16,Layer4Header[2]/16)
assign[streamid=drop;priority=1;tag=port1]=(Layer3Protocol==IPV4)and(port==1)and(Key(KDEF2)==7)
assign[streamid=drop;priority=1;DestinationPort=0;tag=port1]=(Layer3Protocol==IPV4)and(port==1)and(Key(KDEF2)==9)
```
###### IPv6 filters:
```
KeyType[name=KT3;Access=partial;Bank=0;KeyID=3;tag=port1]={128,128,16,16}
KeyDef[name=KDEF3;KeyType=KT3;prot=OUTER;tag=port1]=(Layer3Header[8]/128,Layer3Header[24]/128,Layer4Header[0]/16,Layer4Header[2]/16)
assign[streamid=drop;priority=1;tag=port1]=(Layer3Protocol==IPV6)and(port==1)and(Key(KDEF3)==8)
assign[streamid=drop;priority=1;DestinationPort=0;tag=port1]=(Layer3Protocol==IPV6)and(port==1)and(Key(KDEF3)==10)
```
##### Flow matcher stream
When DPDK is initialized all flow matcher streams are created in order to be ready when the packets arrives.
The new flow matcher API is used to create the streams.

- NT_FlowOpenAttrInit
- NT_FlowOpenAttrSetAdapterNo
- NT_FlowOpen_Attr

## DPDK changes made to support flow matcher
Very early in the development it was clear that the normal DPDK filter programming API rte_flow was much to slow to be used to program flows to the adapter. The nature of the rte_flow is not made for fast special purpose programming, but is made for generic advanced programming.

It was decided to create a new Napatech flow programming command in DPDK.

##### rte_flow_program (API)
The rte_flow_program function is a pure binary function by this it means that no parameters has to be converted to text like rte_flow and NTPL.

The parameters taken by the function are:

- port_id
  DPDK Port ID - Used to find the right setting for the DPDK port used.
- queue_id  
  DPDK Queue ID - Used to find the right setting for the DPDK queue.
  In order to ensure that the function is thread safe, only one queue ID must be used per thread.
- tuple
  Parameters for the flow matcher. Described later.
- error
  DPDK error message return.  

```
int rte_flow_program(uint16_t port_id, uint16_t queue_id, struct rte_flow_5tuple *tuple, struct rte_flow_error  *error);
```
######tuple - Flow matcher parameter:
The tuple struct is similar to the one used by the flow write command, but it is not the same.
```
struct rte_flow_5tuple {
  uint8_t port;
  uint32_t flag;
  union {
    struct {
      uint32_t src_addr;         /**< source address */
      uint32_t dst_addr;         /**< destination address */
    } IPv4;
    struct {
      uint8_t  src_addr[16]; /**< IP address of source host. */
      uint8_t  dst_addr[16]; /**< IP address of destination host(s). */
    } IPv6;
  } u;
  uint16_t src_port;         /**< Source port. */
  uint16_t dst_port;         /**< Destination port. */
  uint8_t proto;             /**< Protocol. */
};
```

The flag mask values are:

| Mask value | Description |
|------------|-------------|
| RTE_FLOW_PROGRAM_DROP_ACTION | The containing flow must be dropped |
| RTE_FLOW_PROGRAM_FORWARD_ACTION | The containing flow must be forwarded to  `port` |
| RTE_FLOW_PROGRAM_IPV4 | The flow is an IPv4 flow |
| RTE_FLOW_PROGRAM_IPV6 | The flow is an IPv6 flow |
| RTE_FLOW_PROGRAM_INNER | The flow is an inner packet (tunnel) |
 
##### _dev_flow_match_program
The API command rte_flow_program will result in a call to the PMD driver function _dev_flow_match_program.
The _dev_flow_match_program function will handle the flow programming using the NT_FlowWrite command as well as it will setup the flow matcher filters when the first packet arrives.

## DAQ/Snort changes made to support flow matcher
In order to support the flow matcher, Snot has to setup a forward or drop filter to offload all the traffic to the hardware. This should be done when a verdict of DAQ_VERDICT_WHITELIST, DAQ_VERDICT_BLACKLIST or DAQ_VERDICT_IGNORE is received from Snort.
 
Following function will handle the filter setup:

```
static inline int create_packet_filter(struct rte_mbuf *mb, DAQ_Verdict verdict, uint8_t port, DpdkDevice *peer, uint16_t queue, int debug, int flowMatcherSupport)
```

The function is called every time Snort returns from it's callback with the right verdict.

```
if (callback) {
  verdict = callback(user, &daqhdr, data);

  if (verdict != DAQ_VERDICT_PASS && verdict != DAQ_VERDICT_REPLACE && !dpdk_intf->noOffload)
     create_packet_filter(bufs[i], verdict, device->port, peer, dev_queue, dpdk_intf->debug, dpdk_intf->flowMatcherSupport);

  if (verdict >= MAX_DAQ_VERDICT)
    verdict = DAQ_VERDICT_PASS;

  dpdk_intf->stats.verdicts[verdict]++;
  verdict = verdict_translation_table[verdict];
}
```

create_packet_filter will call the offload_filter_setup function which will handle all filter creation. 

```
static inline int offload_filter_setup(struct rte_mbuf *mb, DAQ_Verdict verdict, uint8_t port, DpdkDevice *peer, uint16_t queue, int debug, int flowMatcherSupport)
```

##### Snort option to handle flow matcher and the DAQ
Some options can be used to setup DAQ and DPDK when starting Snort

| option | Description |
|--------|-------------|
| --daq-var debug | Enable some debug printout |
| --daq-var nooffload | Disable hardware offload |
| --daq-var dpdk_argc="-n4 -c0x1F0 --log-level=ntacc,8" | Send options to DPDK<br>Note: There must not  a be space between the DPDK option and the value |

To be used like below:
```
./snort --daq dpdk --daq-var dpdk_argc="-n4 -c0x1F0" --daq-var debug -i "dpdk0:dpdk1" -Q -z 4 -k none -c /opt/snort/etc/snort/snortconv.lua
```

#### Packet CRC errors `-k none`
The present 4GA SmartNics cannot recalculate the IP CRC, this means that all altered packets like when running TREX will have a CRC error when received by Snort. Again, this means that Snort will ignore the packets.
In order to get Snort to accept the packets with CRC error the `-k none` option must be used when starting Snort. 
 
 
