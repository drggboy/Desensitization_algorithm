import java.text.SimpleDateFormat;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.codec.digest.DigestUtils;

import com.google.common.hash.Hashing;

/**
 * 脱敏算法
 */
public class Desensitization_Algorithm{
	//随机盐值的长度，用于哈希脱敏
	private static final int SALT_LENGTH = 6;
	
    /**
     * 脱敏算法类型：哈希脱敏<br>
     * 脱敏算法1：MD5、SHA-1、HMAC<br>
     * <br>
     * HMAC 待实现<br>
     * <br>
     * 示例如下：<br>
     * 输⼊：13800001234<br>
     * 参数：随机盐值<br>
     * 输出：67EF569E4167362261FEAB2ECD9CDE9D<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_1 = Hash_Md5_Sha1("MD5","13800001234")
     * 
     * @param type 				  加密方法：“MD5”、“SHA1”、“HMAC”
     * @param sourcePassword      待加密字符串
     * @return 加密后的字符串
     */
	public static String Hash_Md5_Sha1(String type, String sourcePassword) {
        String salt = RandomStringUtils.randomAlphanumeric(SALT_LENGTH);
        sourcePassword = String.format("%s%s", sourcePassword, salt);
        String encryptedText = "";
        switch (type) {
            case "MD5":
                encryptedText = DigestUtils.md5Hex(sourcePassword.getBytes());
                break;
            case "SHA1":
                encryptedText = DigestUtils.sha1Hex(sourcePassword.getBytes());
                break;
        }
        return String.format("%s", encryptedText);
    }
	
	/**
	 * 脱敏算法类型：掩码脱敏<br>
	 * 脱敏算法2：掩盖指定位的字符<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：13800001234<br>
     * 参数：n=3，m=4，遮盖符*<br>
     * 输出：138****1234<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_2 = mask_char("13945678952",3,4,'*')
	 * 
	 * @param phon_num		待脱敏字符串
	 * @param left			要保留的前 left 位
	 * @param right			要保留的后 right 位
	 * @param c				用于覆盖的字符，如 “*”
	 * @return				覆盖指定位后的字符串
	 */
	public static String mask_char(String phon_num, int left, int right, char c) {
		//遮盖指定位字符
		// 输入字符串为空，则返回空字符串
		if (StringUtils.isBlank(phon_num)) {
            return "";
        }
		// 指定的位数大于总位数则报错
		if (right > phon_num.length() || left>phon_num.length()) {
			System.out.println("请输入正确的指定位！");
			throw new ArithmeticException();
		}
		String left_part = StringUtils.left(phon_num, left);
		
		int c_num = StringUtils.length(phon_num) - left - right;
		String c_part = StringUtils.repeat(c, c_num);
		String right_part = StringUtils.right(phon_num, right);
		String result = left_part + c_part + right_part;
		return result;
		
	}
	
	/**
	 * 脱敏算法类型：掩码脱敏<br>
	 * 脱敏算法3：保留指定位的字符<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：13800001234<br>
     * 参数：n=3，m=7，遮盖符#<br>
     * 输出：###0000####<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_3= char_reserve("13945678952",4,7,'#')
	 * 
	 * @param phon_num		待处理字符串
	 * @param left			保留位从左边第left位开始（从1开始数）
	 * @param right			保留位从左边第right位结束（从1开始数）
	 * @param c				保留位之外的字符用 c 覆盖
	 * @return				保留指定位后的字符串
	 */
	public static String char_reserve(String phon_num,int left, int right, char c) {
		//保留指定位字符
		if (StringUtils.isBlank(phon_num)) {
            return "";
        }
		if (left>=right||left>phon_num.length()||left<=0) {
			System.out.println("请输入正确的指定位！");
			throw new ArithmeticException();
		}
		String c_part = StringUtils.substring(phon_num, left-1, right);
		String left_part = StringUtils.repeat(c, left-1);
		int right_num = StringUtils.length(phon_num) - right;
		String right_part = StringUtils.repeat(c, right_num);
		String result = left_part + c_part + right_part;
		return result;
	}

	/**
	 * 脱敏算法类型：掩码脱敏<br>
	 * 脱敏算法4：特殊字符前遮盖<br>
	 * 此处仅针对第一个特殊字符前的字符串进行覆盖<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：1380000@qq.com<br>
     * 参数：@，遮盖符*<br>
     * 输出：*******@qq.com<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_4 = particular_before("835547752@qq.com",'@','*')
	 * 
	 * @param email_like		待处理字符串
	 * @param parlar			特殊字符
	 * @param y					用于覆盖的字符
	 * @return					返回特殊字符前遮盖的字符串
	 */
	public static String particular_before(String email_like,char parlar, char y) {
		//特殊字符前
		if (StringUtils.isBlank(email_like)) {
            return "";
        }
		String after_part = StringUtils.substringAfter(email_like,parlar);
		int forward_num = StringUtils.length(email_like) - StringUtils.length(after_part) - 1;
		String forward_part = StringUtils.repeat(y, forward_num);
		String result = forward_part +  parlar + after_part;
		return result;
	}
	
	/**
	 * 脱敏算法类型：掩码脱敏<br>
	 * 脱敏算法5：特殊字符后遮盖<br>
	 * <br>
	 * 此处仅针对第一个特殊字符后的字符串进行覆盖<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：test.name<br>
     * 参数：., 遮盖符# <br>
     * 输出：test.#### <br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_5 = particular_after("test.name", '.', '#')
	 * 
	 * @param obj		待处理字符串
	 * @param parlar	特殊字符
	 * @param y			用于覆盖的字符
	 * @return			返回特殊字符后覆盖的字符串
	 */
	public static String particular_after(String obj,char parlar, char y) {
		//特殊字符后
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		String forward_part = StringUtils.substringBefore(obj,parlar);
		String after = StringUtils.substringAfter(obj,parlar);
		int after_num = StringUtils.length(after);
		String after_part = StringUtils.repeat(y, after_num);
		String result = forward_part + parlar + after_part;
		return result;
	}
	
	/**
	 * 脱敏算法类型：替换脱敏<br>
	 * 脱敏算法6：码表替换<br>
	 * <br>
	 * 此处仅实现针对两个不同字符进行替换的功能<br>
	 * 后续考虑实现：输入码表后，替换相应字符<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：13800001234<br>
     * 参数：0->A,1->B<br>
     * 输出：B38AAAAB234<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_6 = char_substitute("13800001234","0","A","1","B")
	 * 
	 * @param obj			待处理字符串
	 * @param raw_1			待替换字符1
	 * @param to_1			用于替换字符1
	 * @param raw_2			待替换字符2
	 * @param to_2			用于替换字符2
	 * @return				替换脱敏后的字符串
	 */
	public static String  char_substitute(String obj,String raw_1, String to_1, String raw_2, String to_2) {
		//随机替换
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		String S = StringUtils.replace(obj, raw_1, to_1);
		S = StringUtils.replace(S, raw_2, to_2);
		return S;
	}
	
	/**
	 * 脱敏算法类型：替换脱敏<br>
	 * 脱敏算法7：随机替换<br>
	 * <br>
	 * 此函数用相同位数随机数替换相应的字符串片段<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：13800001234<br>
     * 参数：n=3，m=4，随机码<br>
     * 输出：13843211234<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_7 = rand_substitute("13800001234",3,4)
	 * 
	 * @param obj		待处理字符串
	 * @param left		左边left位保留
	 * @param right		右边right位保留
	 * @return			随机替换后的字符串
	 */
	public static String rand_substitute(String obj,int left, int right) {
		// 随机替换
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		int rand_num = StringUtils.length(obj) - left - right;
		String rand = RandomStringUtils.random(rand_num, false, true);
		String result = StringUtils.overlay(obj, rand, left, left + rand_num);
		return result;
	}
	
	/**
	 * 脱敏算法类型：变换脱敏<br>
	 * 脱敏算法8：数字去精度<br>
	 * <br>
	 * 整数部分保留前n位，剩余部分取0，小数部分保留m位，剩余部分删去（不做四舍五入）<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：103.1415<br>
     * 参数：n=1，m=2<br>
     * 输出：100.14<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_8 = digital_precision("103.1415",1,2)
	 * 
	 * @param obj		待处理字符串
	 * @param left		整数部分保留位数
	 * @param right		小数部分保留位数
	 * @return			脱敏字符串
	 */
	public static String  digital_precision(String obj,int left, int right) {
		// 数字去精度
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		String left_part_raw = StringUtils.substringBefore(obj, '.');
		String right_part_raw = StringUtils.substringAfter(obj, '.');
		int left_part_raw_num = StringUtils.length(left_part_raw);
		String left_pre = StringUtils.left(left_part_raw, left);
		String left_part = StringUtils.rightPad(left_pre, left_part_raw_num, "0");
		String right_part = StringUtils.left(right_part_raw, right);
		String result = left_part + '.' + right_part;
		return result;
	}
	
	/**
	 * 脱敏算法类型：变换脱敏<br>
	 * 脱敏算法9：日期取整<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：2022/06/16 17:20:15<br>
     * 参数：小时<br>
     * 输出：2022/06/16 17:00:00<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_9 = date_change("2022/06/16 17:20:15","小时")
	 * 
	 * @param obj		待处理字符串
	 * @param s			"年"、"月"、"日"、"小时"、"分钟"
	 * @return			脱敏字符串
	 */
	public static String date_change(String obj,String s){
		// 日期取整
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		SimpleDateFormat ft = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date date;
		try {
			date = ft.parse(obj);
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			System.out.println("日期解析错误");
			date = new Date();
		}
		Date round_date;
		switch (s) { 
		    case "年": 
		    	round_date = DateUtils.round(date,Calendar.YEAR);
		        break;
		    case "月": 
		    	round_date = DateUtils.round(date,Calendar.MONTH);
		        break; 
		    case "日": 
		    	round_date = DateUtils.round(date,Calendar.HOUR_OF_DAY);
		        break;
		    case "小时": 
		    	round_date = DateUtils.round(date,Calendar.HOUR);
		        break;
		    case "分钟": 
		    	round_date = DateUtils.round(date,Calendar.MINUTE);
		        break;
		    default:
		    	round_date = new Date();
    	}
		String result = ft.format(round_date);
		return result;
	}
	
	/**
	 * 脱敏算法类型：变换脱敏<br>
	 * 脱敏算法10：字符位移<br>
	 * <br>
	 *    字符串整体向左或向右循环位移bit位<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：13800001234<br>
     * 参数：5位，向右<br>
     * 输出：01234138000<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_10 = char_shift("13800001234",5,"向右")
	 * 
	 * @param obj			待处理字符串
	 * @param bit			位移位数
	 * @param direction		"向左"、"向右"
	 * @return				脱敏字符串
	 */
	public static String char_shift(String obj, int bit, String direction) {
		//字符位移
		if (StringUtils.isBlank(obj)) {
	        return "";
	    }
		int length = obj.length();
		String right_part;
		String left_part;
		if(direction == "向左") {
			right_part = StringUtils.left(obj, bit);
			left_part = StringUtils.right(obj, length - bit);
		}
		else {
			right_part = StringUtils.left(obj, length - bit);
			left_part = StringUtils.right(obj, bit);
		}
		String result = left_part + right_part;
		return result;
	}
	
	/**
	 * 脱敏算法类型：加密脱敏<br>
	 * 脱敏算法11：DES、3DES、AES<br>
	 * <br>
	 * 		目前只实现DES加解密<br>
	 * 		此处为DES加密<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：13800001234<br>
     * 参数：密钥<br>
     * 输出：U2FsdGVkX19K9GhuLfmquNaRmLiLq+mEGdNY7hGfaP4=<br>
     * <br>
     * 调用方式：<br>
     * 		String DES_encode = DES_enc("13800001234","12345678")
     * 
	 * @param plainText		待处理字符串
	 * @param originKey		密钥
	 * @return				DES加密字符串
	 * @throws Exception	加密失败
	 * 
	 */
	public static String DES_enc(String plainText,String originKey) throws Exception {
        System.out.print("明文：" + plainText + "     ");
        System.out.print("密钥：" + originKey + "     ");
        
        SecretKeySpec key = new SecretKeySpec(originKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encipherByte = cipher.doFinal(plainText.getBytes());
        String encode = Base64.getEncoder().encodeToString(encipherByte);
        System.out.println("加密：" + encode + "     ");
        return encode;
    }
	
	/**
	 * 脱敏算法类型：加密脱敏<br>
	 * 脱敏算法11：DES、3DES、AES<br>
	 * <br>
	 * 		目前只实现DES加解密<br>
	 * 		此处为DES解密<br>
     * <br>
     * 调用方式：<br>
     * 		String DES_dncode = DES_dnc(DES_encode,"12345678")
     * 
	 * @param plainText		待处理字符串
	 * @param originKey		密钥
	 * @return				DES解密字符串
	 * @throws Exception	加密失败
	 * 
	 */
	public static String DES_dnc(String plainText,String originKey) throws Exception {
        System.out.print("密文：" + plainText + "     ");
        System.out.print("密钥：" + originKey + "     ");
        SecretKeySpec key = new SecretKeySpec(originKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");

        
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decode = Base64.getDecoder().decode(plainText);
        byte[] decipherByte = cipher.doFinal(decode);
        String decipherText = new String(decipherByte);
        System.out.println("解密：" + decipherText + "     ");
        return decipherText;
    }
	
	/**	 
	 * 脱敏算法12：分桶脱敏<br>
	 * <br>
	 * 示例如下：<br>
     * 输⼊：血压高压值190<br>
     * 参数：140以上->高血压，90〜140->正常血压，90以下->低血压<br>
     * 输出：高血压<br>
     * <br>
	 * 调用方式：<br>
	 * 		String alg_12 = Bucket_desensitization("190");<br>
	 * 
	 * @param pressure		血压值
	 * @return				高血压、正常血压、低血压
	 */
	public static String Bucket_desensitization(String pressure) {
		//分桶脱敏
		if (StringUtils.isBlank(pressure)) {
            return "";
        }
		int value = Integer.parseInt(pressure);
		String result;
		if(value > 140)
			result = "高血压";
		else if(value >= 90)
			result = "正常血压";
		else
			result = "低血压";
		return result;
	}
	
	/**
	 * 	在主方法中调用了各个脱敏算法的实例，并将结果打印输出
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception{
		String alg_1 = Hash_Md5_Sha1("MD5","13800001234");
		System.out.println(alg_1);
		// 哈希脱敏: 180e5d114eb2067827b9a64ccd4309f7
		
		String alg_2 = mask_char("13945678952",3,4,'*');
		System.out.println(alg_2);
		// 遮盖指定位的字符: 139****8952
		
		String alg_3= char_reserve("13945678952",4,7,'#');
		System.out.println(alg_3);
		// 保留指定位的字符: ###4567####
		
		String alg_4 = particular_before("835547752@qq.com",'@','*');
		System.out.println(alg_4);
		// 特殊字符前遮盖:  *********@qq.com
		
		String alg_5 = particular_after("test.name",'.','#');
		System.out.println(alg_5);
		// 特殊字符后遮盖: test.####
		
		String alg_6 = char_substitute("13800001234","0","A","1","B");
		System.out.println(alg_6);
		// 码表替换: B38AAAAB234
		
		String alg_7 = rand_substitute("13800001234",3,4);
		System.out.println(alg_7);
		// 随机替换: 13861481234
		
		String alg_8 = digital_precision("103.1415",1,2);
		System.out.println(alg_8);
		// 数字去精度: 1000.14
		
		String alg_9 = date_change("2022/06/16 17:20:15","小时");
		System.out.println(alg_9);
		// 日期取整: 2022/06/16 17:00:00

		String alg_10 = char_shift("13800001234",5,"向右");
		System.out.println(alg_10);
		// 字符位移： 01234138000
		
		// DES加密脱敏
		String DES_encode = DES_enc("13800001234","12345678");
		// 明文：13800001234     密钥：12345678     加密：bjFSssnneRgM2VDdO7lO7g==     
		String DES_dncode = DES_dnc(DES_encode,"12345678");
		// 密文：bjFSssnneRgM2VDdO7lO7g==     密钥：12345678     解密：13800001234     
		
		String alg_12 = Bucket_desensitization("190");
		System.out.println(alg_12);
		// 分桶脱敏: 高血压
	}
}
