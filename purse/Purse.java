package purse;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import sampleLoyalty.JavaLoyaltyInterface;

public class Purse extends Applet {
	/* constants declaration */

	  // code of CLA byte in the command APDU header
	  final static byte Wallet_CLA =(byte)0x80;

	  // codes of INS byte in the command APDU header
	  final static byte VERIFY = (byte) 0x20;
	  final static byte CREDIT = (byte) 0x30;
	  final static byte DEBIT = (byte) 0x40;
	  final static byte DEBIT_POINT = (byte) 0x41; //新�?�的消费�?分功�?
	  final static byte GET_BALANCE = (byte) 0x50;
	  final static byte GET_RECORD = (byte) 0x60; //新�?�的读取记录功能
	  final static byte SIGNATURE_MAC = (byte) 0x70; //新�?�的MAC签名功能
	  final static byte GET_RANDOM = (byte) 0x80; //新�?�获取随机数功能
	  final static byte OUT_CERT = (byte) 0x82; //新�?�的外部认证功能
	  final static byte IN_CERT = (byte) 0x84; //新�?�的内部认证功能

	  // maximum balance
	  final static short MAX_BALANCE = 0x7FFF;
	  // maximum transaction amount
	  final static byte MAX_TRANSACTION_AMOUNT = 127;

	  // maximum number of incorrect tries before the
	  // PIN is blocked
	  final static byte PIN_TRY_LIMIT =(byte)0x03;
	  // maximum size PIN
	  final static byte MAX_PIN_SIZE =(byte)0x08;

	  // signal that the PIN verification failed
	  final static short SW_VERIFICATION_FAILED = 0x6300;
	  // signal the the PIN validation is required
	  // for a credit or a debit transaction
	  final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	  // signal invalid transaction amount
	  // amount > MAX_TRANSACTION_AMOUNT or amount < 0
	  final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

	  // signal that the balance exceed the maximum
	  final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
	  // signal the the balance becomes negative
	  final static short SW_NEGATIVE_BALANCE = 0x6A85;

	  //设置�?分应用的aid
	  byte [] loyaltyAIDValue = {(byte)0x11,(byte)0x22,(byte)0x33,(byte)0x44,
			  (byte)0x55,(byte)0x01 };
	  
	  private byte[] keyData = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	  
	  byte[] AppletID = { (byte) 0x11, (byte) 0x22, (byte) 0x33,
	            (byte) 0x44, (byte) 0x55, (byte) 0x03 };
	  
	  byte[] tmp = new byte[10]; //验证数据临时数组
	  byte[] sigbuf = new byte[10]; //验证数据临时数组
	  
	  /* instance variables declaration */
	  OwnerPIN pin;
	  short balance;
	  CyclicFile record;
	  private DESKey indeskey;//接口
	  Cipher  inCipherObj;//类，一�?加密解密和这�?类有�?
	  byte [] Random;//随机数数�?
	  private DESKey outdeskey;
	  Cipher  outCipherObj;
	  private DESKey mackey;  //mac密钥
	  Signature sig;   //mac签名对象

	  private Purse (byte[] bArray,short bOffset,byte bLength){
		  
		record=new CyclicFile((short)20, (short)5);
		  byte pinInitValue[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };

		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		pin.update(pinInitValue, (short) 0, (byte) 6);
	    
	      //pin = new OwnerPIN(PIN_TRY_LIMIT,   MAX_PIN_SIZE);

	    /*byte iLen = bArray[bOffset]; // aid length
	    bOffset = (short) (bOffset+iLen+1);
	    byte cLen = bArray[bOffset]; // info length
	    bOffset = (short) (bOffset+cLen+1);
	    byte aLen = bArray[bOffset]; // applet data length
	    
	    // The installation parameters contain the PIN
	    // initialization value
	    pin.update(bArray, (short)(bOffset+1), aLen);*/
	    register();

	  } 

	  public static void install(byte[] bArray, short bOffset, byte bLength){

	    new Purse(bArray, bOffset, bLength);
	  } 

	  public boolean select() {

	    // The applet declines to be selected
	    // if the pin is blocked.
	    if ( pin.getTriesRemaining() == 0 )
	       return false;
	    else
	       return true;

	  }
	  
	  public void deselect() {

	    // reset the pin value
	    pin.reset();

	  }
	    
	  public void process(APDU apdu) {

	    byte[] buffer = apdu.getBuffer();
	    
	    buffer[ISO7816.OFFSET_CLA] = (byte)(buffer[ISO7816.OFFSET_CLA] & (byte)0xFC);
	    
	    if ((buffer[ISO7816.OFFSET_CLA] == 0) &&
	       (buffer[ISO7816.OFFSET_INS] == (byte)(0xA4)) )
	      return;

	    if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA)
	       ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

	    switch (buffer[ISO7816.OFFSET_INS]) {
	      case GET_RECORD:   getRecord(apdu);
          					  return;
	      case GET_BALANCE:   getBalance(apdu);
	                          return;
	      case DEBIT:         debit(apdu);
	                          return;
	      case DEBIT_POINT:   debitPoint(apdu);
          					  return;
	      case CREDIT:        credit(apdu);
	                          return;
	      case VERIFY:        verify(apdu);
	                          return;
	      case SIGNATURE_MAC: GenerateSignature(apdu);
          					  return;
	      case IN_CERT:       indoAuthentication(apdu);
          					  return;
	      case GET_RANDOM:    getRandom(apdu);
			                  return;
	      case OUT_CERT:      outdoAuthentication(apdu);
			                  return;
	      default:       ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	    }

	 }   // end of process method

	 private void credit(APDU apdu) {

	   // access authentication
	   if ( ! pin.isValidated() )
	 ISOException.throwIt(
	        SW_PIN_VERIFICATION_REQUIRED);

	   JCSystem.beginTransaction(); 
	   byte[] buffer = apdu.getBuffer();

	    // Lc byte denotes the number of bytes in the
	    // data field of the command APDU
	    byte numBytes = buffer[ISO7816.OFFSET_LC];

	    // indicate that this APDU has incoming data
	    // and receive data starting from the offset
	    // ISO7816.OFFSET_CDATA following the 5 header
	    // bytes.
	    byte byteRead = (byte)(apdu.setIncomingAndReceive());

	    // it is an error if the number of data bytes
	    // read does not match the number in Lc byte
	    if ( ( numBytes != 9 ) || (byteRead != 9) )
	     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	    // get the credit amount
	    byte creditAmount = buffer[ISO7816.OFFSET_CDATA];
	    tmp[0] = creditAmount;
        tmp[1] = (byte)0x30; //存�?�标识�??0x30
        Util.arrayCopy(AppletID,(short)0,tmp, (short)2, (short)6); // 加入AID

        if (!VerifySignature(buffer))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

	    // check the credit amount
	    if ( ( creditAmount > MAX_TRANSACTION_AMOUNT)
	         || ( creditAmount < 0 ) )
	        ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);

	    // check the new balance
	    if ( (short)( balance + creditAmount)  > MAX_BALANCE )
	       ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);

	    // credit the amount
	    balance = (short)(balance + creditAmount);
	    
	    record.AppendRecord(buffer, (short)14);
	    
	    grantPoints(CREDIT, creditAmount);
	    
	    JCSystem.commitTransaction();

	  } // end of deposit method

	  private void debit(APDU apdu) {
		  
	    // access authentication
	    if ( ! pin.isValidated() )
	       ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

	    JCSystem.beginTransaction();
	    
	    byte[] buffer = apdu.getBuffer();

	    byte numBytes = (byte)(buffer[ISO7816.OFFSET_LC]);

	    byte byteRead = (byte)(apdu.setIncomingAndReceive());

	    if ( ( numBytes != 9 ) || (byteRead != 9) )
		     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		    // get the credit amount
		    byte debitAmount = buffer[ISO7816.OFFSET_CDATA];
		    tmp[0] = debitAmount;
	        tmp[1] = (byte)0x40; //存�?�标识�??0x30
	        Util.arrayCopy(AppletID,(short)0,tmp, (short)2, (short)6); // 加入AID
	        
	        if (!VerifySignature(buffer))
	            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

	    // check debit amount
	    if ( ( debitAmount > MAX_TRANSACTION_AMOUNT)
	         ||  ( debitAmount < 0 ) )
	       ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);

	    // check the new balance
	    if ( (short)( balance - debitAmount ) < (short)0 )
	         ISOException.throwIt(SW_NEGATIVE_BALANCE);

	    balance = (short) (balance - debitAmount);
	    
	    record.AppendRecord(buffer, (short)14);
	    
	    JCSystem.commitTransaction();

	  } // end of debit method
	  
	  private void debitPoint(APDU apdu) {
		  
		  if ( ! pin.isValidated() )
				 ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		  
		  JCSystem.beginTransaction();
		  if ( ! pin.isValidated() )
		       ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

		    byte[] buffer = apdu.getBuffer();

		    byte numBytes = (byte)(buffer[ISO7816.OFFSET_LC]);

		    byte byteRead = (byte)(apdu.setIncomingAndReceive());

		    if ( ( numBytes != 1 ) || (byteRead != 1) )
		       ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		    // get debit amount
		    byte debitAmount = buffer[ISO7816.OFFSET_CDATA];
		    
		    grantPoints(DEBIT, debitAmount);
		    JCSystem.commitTransaction();
	  }

	  private void getBalance(APDU apdu) {

	    byte[] buffer = apdu.getBuffer();

	    // inform system that the applet has finished
	    // processing the command and the system should
	    // now prepare to construct a response APDU
	    // which contains data field
	    short le = apdu.setOutgoing();

	    if ( le < 2 )
	       ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

	    //informs the CAD the actual number of bytes
	    //returned
	    apdu.setOutgoingLength((byte)2);

	    // move the balance data into the APDU buffer
	    // starting at the offset 0
	    buffer[0] = (byte)(balance >> 8);
	    buffer[1] = (byte)(balance & 0xFF);

	    // send the 2-byte balance at the offset
	    // 0 in the apdu buffer
	    apdu.sendBytes((short)0, (short)2);

	  } // end of getBalance method
	  
	  private void getRecord(APDU apdu) {
		  
		  if ( ! pin.isValidated() )
				 ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		  
		  JCSystem.beginTransaction();
		  
			byte[] buffer=apdu.getBuffer();
			byte[] data;
			
			short num = 0;
			if(buffer[ISO7816.OFFSET_P2]==0x04)
			{
				num = Util.makeShort((byte)0x00,buffer[ISO7816.OFFSET_P1]);
			}
			else if(buffer[ISO7816.OFFSET_P2]==0x00)
			{
				// 空白，�?��?�的 num 为初始�? 0
			}
			else
			{
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}
			if(num>record.maxrecord)
			{
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			}
			if(record.currentrecord == -1)
			{
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			// 尝试读取倒数�? num + 1 条写入的记录内�??
			num = (short)(record.currentrecord-num);
			if(num<=0)
			{
				num = (short)(record.maxrecord+num);
			}
			data=record.ReadRecord(num);
			
			//改变传输方向为发送（卡片到终�?�?
			apdu.setOutgoing();
			apdu.setOutgoingLength(record.recordsize);
			apdu.sendBytesLong(data,(short)0,record.recordsize);
			
			JCSystem.commitTransaction();
		}

	  private void verify(APDU apdu) {

	    byte[] buffer = apdu.getBuffer();
	    // retrieve the PIN data for validation.
	 
	    byte byteRead = (byte)(apdu.setIncomingAndReceive());
	  // check pin
	    // the PIN data is read into the APDU buffer
	  // at the offset ISO7816.OFFSET_CDATA
	  // the PIN data length = byteRead
	  if ( pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false )
	     ISOException.throwIt(SW_VERIFICATION_FAILED);

	} // end of validate method
	  
	  private void indoAuthentication(APDU apdu) {
			
		  byte[] buffer = apdu.getBuffer();
		  apdu.setIncomingAndReceive();
		  //生成密钥对象
		  indeskey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
	      //设置ＤＥＳ密�?					
	      indeskey.setKey(keyData, (short)0);
	      //生成加密对象，获取一个DES_CBC模式的实�?
		  inCipherObj   = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	      //初�?�化密钥及加密模�?
	      inCipherObj.init(indeskey, Cipher.MODE_ENCRYPT);
	      //加密，将buffer从�??5位开始后�?8位加密放在buffer�?0位开�?
	      inCipherObj.doFinal(buffer, (short)5, (short)8, buffer, (short)0);
	      apdu.setOutgoingAndSend((short)0, (short)8);
	}
	 
	  private void outdoAuthentication(APDU apdu) {
			
		  byte[] buffer = apdu.getBuffer();
		  apdu.setIncomingAndReceive();		  
		  //生成密钥对象
	      outdeskey=(DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);						
	      //设置ＤＥＳ密�?					
	      outdeskey.setKey(keyData, (short)0);	      
	      //生成加密对象
	      outCipherObj   = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);      
	      //初�?�化密钥及加密模�?
	      outCipherObj.init(outdeskey, Cipher.MODE_ENCRYPT);      
	      //加密
	      outCipherObj.doFinal(Random, (short)0, (short)8, buffer, (short)13); 	       
	      //比较数据域与加密结果
	      if ( Util.arrayCompare(buffer,(short)5, buffer, (short)13,(short)8) != 0)
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}
	  
	  private void getRandom(APDU apdu) {
			
		    byte[] buffer = apdu.getBuffer();
		  
		    //创建存放随机数的数组
		    if ( Random == null )
				Random = JCSystem.makeTransientByteArray((short)16,JCSystem.CLEAR_ON_DESELECT);
			
			//获得生成随机数的对象实例
			RandomData ICC = RandomData.getInstance((byte)RandomData.ALG_PSEUDO_RANDOM );
			
			//设置随机数的种子并产�?8字节的随机数
			ICC.setSeed(Random,(short)0,(short)8 );
			//真随机数使用�?声随机生成，采取的是电�?�的电压，真随机数需要等待，时间较长
	        ICC.generateData(Random,(short)0,(short)8);
	        
	        //返回生成�?8字节随机�?
			Util.arrayCopyNonAtomic(Random,(short)0,buffer,(short)0,(short)8);
			apdu.setOutgoingAndSend((short)0, (short)8);
		}
	  
	  //签名
	  private void GenerateSignature(APDU apdu) {

	        byte[] buffer = apdu.getBuffer();
	        apdu.setIncomingAndReceive();
	        
	        mackey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);                    
	        //设置mac密钥                    
	        mackey.setKey(keyData, (short)0);
	        //初�?�化签名对象
	        sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);
	        //初�?�化签名模式
	        sig.init(mackey, Signature.MODE_SIGN);
	                      
	        //对输入数�?进�?��?�名，存放在buffer�?        
	        apdu.setOutgoingAndSend((short)13, sig.sign(buffer, (short)5, (short)8,buffer, (short)13));

	    }
	    
	  //验�??
	  private boolean VerifySignature(byte [] buffer) {
	                      
	    	mackey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);                    
	        //设置mac密钥                    
	        mackey.setKey(keyData, (short)0);
	        //初�?�化签名对象
	        sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);
	        //初�?�化签名模式
	        sig.init(mackey, Signature.MODE_SIGN);
	       //对存放在buffer�?的输入数�?进�?��?�名验证
	        sig.sign(tmp, (short)0, (short)8, sigbuf, (short)0);
	        if(Util.arrayCompare(buffer, (short)6, sigbuf, (short)0, (short)8)!=0)
	            return false;
	        else
	            return true;
			//return sig.verify(tmp, (short)0, (short)8, buffer, (short)6,(short)8);
	    }

	  private void grantPoints(byte type, short points) {

		  //shareable interface & loyalAID local variables
		  JavaLoyaltyInterface loyaltySIO;
		  AID loyaltyAID;
		  
		  //在JCRE�?查找所有已注册的应用AID对象，�?�果和loyaltyAIDValue相同，返回�??AID对象
		  loyaltyAID =  JCSystem.lookupAID(loyaltyAIDValue, (short) (0), (byte)(loyaltyAIDValue.length) );
		  //判断�?否找到，若找到AID，继�?执�?�；否则，表示服务器应用没有注册
		  if (loyaltyAID != null) 
			  //在JCSystem.getAppletShareableInterfaceObject()方法执�?�过程中�?
			  //JCRE将自动调用服务器应用的getShareableInterfaceObject()方法，返回SIO
			  //将返回的引用O强制�?�?为JavaLoyaltyInterface类型，防止其使用对象O的其他功能�?
			  loyaltySIO = (JavaLoyaltyInterface)JCSystem.getAppletShareableInterfaceObject(loyaltyAID, (byte)0);
		  else
			  return;
		  
		  //2 bytes points in buffer at 0 offset	  
		  loyaltySIO.grantPoints(type, points); 
		  
	  }//end of grant points method

}