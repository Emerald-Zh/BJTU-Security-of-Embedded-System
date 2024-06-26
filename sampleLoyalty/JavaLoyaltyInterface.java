package sampleLoyalty;
import javacard.framework.Shareable;
public interface JavaLoyaltyInterface extends Shareable {
	void grantPoints (byte type, short points);}
//接口的定义类
//我多设计一个参数，代表交易类型