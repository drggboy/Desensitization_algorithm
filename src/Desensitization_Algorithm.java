import java.text.SimpleDateFormat;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;

import com.google.common.hash.Hashing;

public class Desensitization_Algorithm{
	public static String Hash_generateMD5(String input) {
        //获取MD5机密实例
		try {
			String result = Hashing.md5().hashBytes(input.getBytes("UTF-8")).toString();
			return result;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "Null";
    }
	
	public static String mask_char(String phon_num, int left, int right, char c) {
		if (StringUtils.isBlank(phon_num)) {
            return "";
        }
		String left_part = StringUtils.left(phon_num, left);
		int c_num = StringUtils.length(phon_num) - left - right;
		String c_part = StringUtils.repeat(c, c_num);
		String right_part = StringUtils.right(phon_num, right);
		String result = left_part + c_part + right_part;
		return result;
	}
	
	public static String char_reserve(String phon_num,int left, int right, char c) {
		if (StringUtils.isBlank(phon_num)) {
            return "";
        }
		String c_part = StringUtils.substring(phon_num, left-1, right);
		String left_part = StringUtils.repeat(c, left-1);
		int right_num = StringUtils.length(phon_num) - right;
		String right_part = StringUtils.repeat(c, right_num);
		String result = left_part + c_part + right_part;
		return result;
	}

	public static String particular_before(String email_like,char parlar, char y) {
		if (StringUtils.isBlank(email_like)) {
            return "";
        }
		String after_part = StringUtils.substringAfter(email_like,parlar);
		int forward_num = StringUtils.length(email_like) - StringUtils.length(after_part) - 1;
		String forward_part = StringUtils.repeat(y, forward_num);
		String result = forward_part +  parlar + after_part;
		return result;
	}
	
	public static String particular_after(String obj,char parlar, char y) {
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
	
	public static String  char_substitute(String obj,String raw_1, String to_1, String raw_2, String to_2) {
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		String S = StringUtils.replace(obj, raw_1, to_1);
		S = StringUtils.replace(S, raw_2, to_2);
		return S;
	}
	
	public static String rand_substitute(String obj,int left, int right) {
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		int rand_num = StringUtils.length(obj) - left - right;
		String rand = RandomStringUtils.random(rand_num, false, true);
		String result = StringUtils.overlay(obj, rand, left, left + rand_num);
		return result;
	}
	
	public static String  digital_precision(String obj,int left, int right) {
		if (StringUtils.isBlank(obj)) {
            return "";
        }
		String left_part_raw = StringUtils.substringBefore(obj, '.');
		String right_part_raw = StringUtils.substringAfter(obj, '.');
		int left_part_raw_num = StringUtils.length(right_part_raw);
		String left_pre = StringUtils.left(left_part_raw, left);
		String left_part = StringUtils.rightPad(left_pre, left_part_raw_num, "0");
		String right_part = StringUtils.left(right_part_raw, right);
		String result = left_part + '.' + right_part;
		return result;
	}
	
	public static String date_change(String obj,String s){
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
	
	public static String char_shift(String obj, int bit, String direction) {
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
	
	public static void DES(String plainText,String originKey) throws Exception {
        System.out.print("明文：" + plainText + "     ");
        
        System.out.print("密钥：" + originKey + "     ");
        SecretKeySpec key = new SecretKeySpec(originKey.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encipherByte = cipher.doFinal(plainText.getBytes());
        String encode = Base64.getEncoder().encodeToString(encipherByte);
        System.out.print("加密：" + encode + "     ");
        
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decode = Base64.getDecoder().decode(encode);
        byte[] decipherByte = cipher.doFinal(decode);
        String decipherText = new String(decipherByte);
        System.out.println("解密：" + decipherText + "     ");
    }
	
	
	public static String Bucket_desensitization(String pressure) {
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
	
	
	public static void main(String[] args) {
		String alg_1 = Hash_generateMD5("13800001234");
		System.out.println(alg_1);
		// 哈希脱敏: 97d2bc5078985f4d0f2fc6d5b7475f80
		
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
		
		try {
			DES("13800001234","12345678");
		} catch (Exception e) {
			e.printStackTrace();
		}
		// DES加密脱敏： 
		// 明文：13800001234     密钥：12345678     加密：bjFSssnneRgM2VDdO7lO7g==     解密：13800001234
		
		String alg_12 = Bucket_desensitization("190");
		System.out.println(alg_12);
		// 分桶脱敏: 高血压
	}
}
