package purse;

import javacard.framework.JCSystem;

public class CyclicFile {
	private byte[] record;//一维，存放所有命令
	public short maxrecord;//最大命令数量
	public short recordsize;//最大命令长度
	public short currentrecord;//目前命令位置
	private byte[] buffer;
	
	protected CyclicFile(short size,short max)
	{
		//持久存储
		recordsize = size;
		maxrecord = max;
		record = new byte[size*max];
		currentrecord = 0;
		//TransientByteArray临时存储，卡片从读卡器拿开，数组数据消失
		buffer = JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
	}
	
	public byte[] ReadRecord(short num)
	{
		for(short i=0;i<recordsize;i++)
		{
			//num是从1开始，命令是从第0条开始
			buffer[i]=record[(num-1)*recordsize+i];
		}
		return buffer;
	}
	
	public short AppendRecord(byte[] data,short size)	
	{
		if(size>recordsize)
		{
			return (short)1;
		}
		//赋值前size字节，输入内容
		for(short i=0;i<size;i++)
		{
			record[currentrecord*recordsize+i]=data[i];
		}
		//赋值其他字节，补0,
		for(short i=size;i<recordsize;i++)
		{
			record[currentrecord*recordsize+i]=(byte)0x00;
		}
		currentrecord++;
		//循环
		if(currentrecord==maxrecord)
		{
			currentrecord=0;
		}
		return (short)0;
	}

}