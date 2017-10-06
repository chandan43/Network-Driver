#define TX_BUF_SIZE  1536  /* should be at least MTU + 14 + 4 */
#define NUM_TX_SIZE 4
#define TOTAL_TX_BUF_SIZE  (TX_BUF_SIZE * NUM_TX_SIZE)
#define ETH_MIN_LEN 60  /* minimum Ethernet frame size */

#define RX_BUF_LEN_IDX 2         /* 0==8K, 1==16K, 2==32K, 3==64K */
#define RX_BUF_LEN     (8192 << RX_BUF_LEN_IDX)
#define RX_BUF_PAD     16           /* see 11th and 12th bit of RCR: 0x44 */
#define RX_BUF_WRAP_PAD 2048   	/* spare padding to handle pkt wrap */
#define RX_BUF_TOT_LEN  (RX_BUF_LEN + RX_BUF_PAD + RX_BUF_WRAP_PAD)


/* 8139 register offsets */
#define TSD0      0x10   // TxStatus
#define TSAD0     0x20   // TxAddr
#define RBSTART   0x30   // RxBuf 
#define CR        0x37   // ChipCmd
#define CAPR      0x38   // RxBufPtr 
#define IMR       0x3C   // IntrMask  
#define ISR       0x3E   // IntrStatus
#define TCR       0x40   // TxConfig 
#define RCR       0x44   // RxConfig
#define MPC       0x4C   // RxMissed
#define MULINT    0x5C   // MultiIntr

/* TSD register commands */
#define TxHostOwns    0x2000 // 
#define TxUnderrun    0x4000
#define TxStatOK      0x8000
#define TxOutOfWindow 0x20000000
#define TxAborted     0x40000000
#define TxCarrierLost 0x80000000

/* CR register commands */
#define RxBufEmpty 0x01
#define CmdTxEnb   0x04
#define CmdRxEnb   0x08
#define CmdReset   0x10

/* ISR Bits */
#define RxOK       0x01
#define RxErr      0x02
#define TxOK       0x04
#define TxErr      0x08
#define RxOverFlow 0x10
#define RxUnderrun 0x20
#define RxFIFOOver 0x40
#define CableLen   0x2000
#define TimeOut    0x4000  // PCSTimeout 
#define SysErr     0x8000  //PCIErr

#define INT_MASK (RxOK | RxErr | TxOK | TxErr | \
               RxOverFlow | RxUnderrun | RxFIFOOver | \
               CableLen | TimeOut | SysErr)

