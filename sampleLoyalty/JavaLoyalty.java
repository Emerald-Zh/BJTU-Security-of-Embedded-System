package sampleLoyalty;

import javacard.framework.*;

//接口的实现类
//继承父类Applet&对JavaLoyaltyInterface接口实现的类
public class JavaLoyalty extends Applet implements JavaLoyaltyInterface {

	  /*
	   *
	   * Constants
	   *
	   */
	  
	  final static byte  LOYALTY_CLA   = (byte) 0x90;  //CLA byte for JavaLoyalty
	  final static byte  READ_BALANCE  = (byte) 0x20;  //INS byte for Read Balance
	  final static byte  RESET_BALANCE = (byte) 0x22;  //INS byte for Reset Balance
	  final static byte  CREDIT        = (byte) 0x30;  //byte for Credit in grantPoints buffer
	  final static byte  DEBIT		   = (byte) 0x40;	//byte for Debit in grantPoints buffer
	  final static short SCALE         = (short) 1; //1 Loyalty Point per $1 (100c) debit
	  final static short BALANCE_MAX   = (short)30000; //One won't get free flight from SFO to LAX
	  //for this amount now, but we don't want to
	  //introduce byte-array arithmetics for this
	  //sample applet
	  short balance;
	  
	  /**
	   * Installs Java Loyalty applet.
	   * @param bArray install parameter array.
	   * @param bOffset where install data begins.
	   * @param bLength install parameter data length.
	   */
	  public static void install( byte[] bArray, 
				      short bOffset,
				      byte bLength )  {
	    new JavaLoyalty(bArray, bOffset, bLength);
	  }
	  
	  /**
	   * Performs memory allocations, initializations, and applet registration
	   *
	   * @param bArray received by install.
	   * @param bOffset received by install.
	   * @param bLength received by install.
	   */
	  protected JavaLoyalty(byte[] bArray, 
				short bOffset, 
				byte bLength) {
	    balance = (short)0;
	    /*
	     * if AID length is not zero register Java Loyalty
	     * applet with specified AID
	     *
	     * NOTE: all the memory allocations should be performed before register()
	     */
	    
	    //这个激活是在干嘛？
	    byte aidLen = bArray[bOffset];
	    if (aidLen== (byte)0){
	      register();
	    } else {
	      register(bArray, (short)(bOffset+1), aidLen);
	    }
	  }
	  
	  /**
	   * Implements getShareableInterfaceObject method of Applet class.
	   * <p>JavaLoyalty could check here if the clientAID is that of JavaPurse
	   * Checking of the parameter to be agreed upon value provides additional
	   * security, or, if the Shareable Interface Object weren't JavaLoyalty itself
	   * it could return different Shareable Interface Objects for different values
	   * of clientAID and/or parameter.
	   * <p>See<em>Java Card Runtime Environment (JCRE) Specification</em> 
	   * for details.
	   *
	   * @param clientAID AID of the client
	   * @param parameter additional parameter
	   * @return JavaLoyalty object
	*/

	  //判断是否给客户权限，如果给就返回此对象o的引用
	  public Shareable getShareableInterfaceObject(AID clientAID,
						       byte parameter)  {
	    if (parameter == (byte)0)
	      return this;
	    else return null;
	  }
	  /**
	   * Implements main interaction with a client. The data is transfered 
	   * through APDU buffer  which is a global array accessible from any 
	   * context. The format of data in the buffer is  subset of Transaction 
	   * Log record format: 2 bytes of 0, 1 byte of transaction type, 2 bytes
	   * amount of transaction, 4 bytes of CAD ID, 3 bytes of date, and 2 bytes 
	   * of time. This sample implementation ignores everything but transaction
	   * type and amount.
	   * @param buffer APDU buffer
	   */
	  
	  public void grantPoints (byte type, short points)  {

	    //balance = (short)(balance + points); 
		switch(type)
		{
			case CREDIT:balance = (short)(balance + points); break;
			case DEBIT:balance = (short)(balance - points); break;
		}

		if (balance < 0) balance = 0;
	    if (balance > BALANCE_MAX) balance = BALANCE_MAX;

	  }

	  /**
	   * Dispatches APDU commands.
	   * @param apdu APDU
	   */
	  public void process(APDU apdu) {
	    byte[] buffer = apdu.getBuffer();
	    // We don't do any additional C-APDU header checking, just rely on
	    // CLA and INS bytes for dispatching.
	    
	    // Mask channel info out
	    //&既是位运算符也是逻辑运算符，&&只是逻辑运算符
	    buffer[ISO7816.OFFSET_CLA] = 
	      (byte)(buffer[ISO7816.OFFSET_CLA] & (byte)0xFC);
	    
	    if (buffer[ISO7816.OFFSET_CLA] == LOYALTY_CLA) {
	      switch (buffer[ISO7816.OFFSET_INS])	{
	      case READ_BALANCE:  processReadBalance(apdu); break;
	      case RESET_BALANCE: processResetBalance(); break;
	      default:
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	      }
	    } 
	    else if (selectingApplet())  //判断是否为select命令
	    	return;
	     else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	  }
	  
	  /**
	   * Sends 2 bytes of balance value in R-APDU.
	   * @param apdu APDU
	   */
	  void processReadBalance(APDU apdu)
	  {
	    byte[] buffer = apdu.getBuffer();
	    Util.setShort(buffer, (short)0, balance);
	    apdu.setOutgoingAndSend((short)0, (short)2);
	  }
	  
	  /**
	   * Resets Balance.
	   */
	  void processResetBalance()  {
	    balance = (short)0;
	  }

}