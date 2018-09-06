package acceleratorCYR.javaxcipherhook;

import android.util.Log;

import java.lang.reflect.Field;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.spec.IvParameterSpec;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

import static de.robv.android.xposed.XposedHelpers.getObjectField;

/**
 * Created by test2016 on 2017/12/1.
 */

public class CryptoInitMethodHook extends XC_MethodHook {


    private String packageName;
    private ClassLoader classLoader;

    private String tag;

    public CryptoInitMethodHook(String packageName, ClassLoader classLoader){
        this.packageName = packageName;
        this.classLoader = classLoader;
        tag = "cyrmethod " + packageName;
    }

    protected String getStackTracesStr(Throwable e){
        StackTraceElement []stackTraces = e.getStackTrace();
        String str="";
        if(stackTraces != null)
        {
            for(int i=0; i< (stackTraces.length < 20? stackTraces.length: 20); i++)
            {
                str +=(String.format("\n      : %s #%s :%s",
                        stackTraces[i].getClassName(),
                        stackTraces[i].getMethodName(), stackTraces[i].getLineNumber()));
            }
            if(stackTraces.length >= 20)
                str +=("\n       ...   ...    \n");
        }

        return str;
    }


    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        //Log.d("cyr" + packageName, "start to hook wechat");

//        Throwable th = new Throwable();
//        StackTraceElement[] stackTraces = th.getStackTrace();
//
//        StringBuffer stackOutput = new StringBuffer(
//                ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\ncyr HookMethodStackTraceBefore  "
//                        + param.getClass().getName());
//
//        if(stackTraces != null)
//        {
//            for(int i=0; i< stackTraces.length; i++)
//            {
//                stackOutput.append(String.format("\n      StackTrace: %s #%s :%s",
//                        stackTraces[i].getClassName(),
//                        stackTraces[i].getMethodName(), stackTraces[i].getLineNumber()));
//            }
//        }
//
//        //Log.i(tag, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
//
//        //Log.i(tag, stackOutput);
//        //StringBuffer outputStr;
//        tryGetEncDecInfo(stackOutput, param);
//
//
//        if(param.args == null)
//            stackOutput.append("\nbefore Call paramsLen: 0" );
//        else {
//            stackOutput.append("\nbefore Call paramsLen:" + param.args.length + " ");
//
//
//            for (int i = 0; i < param.args.length; i++) {
//                if (param.args[i] == null) {
//                    stackOutput.append("\n | param" + Integer.toString(i) + ": "
//                            + "null ");
//                    continue;
//                } else {
//                    stackOutput.append("\n | param" + Integer.toString(i) + ": "
//                            + param.args[i].getClass().getName() + "\t ");
//                }
//
//                //Log.d("cyr tag", String.format("start to analyse param %d", i));
//
//                if (CheckType(param.args[i], String.class)) {
//                    stackOutput.append((String) param.args[i]);
//
//                }
//
//                if (CheckType(param.args[i], byte[].class)) {
//                    OutputByteArray(stackOutput, (byte[]) param.args[i]);
//                }
//
//                if (CheckType(param.args[i], Integer.class)) {
//                    stackOutput.append(Integer.toString((Integer) param.args[i]));
//                } else if (CheckType(param.args[i], int.class)) {
//                    stackOutput.append(Integer.toString((Integer) param.args[i]));
//                }
//            }
//        }
//
//        Log.i(tag, stackOutput.toString());
//        super.beforeHookedMethod(param);
    }

    protected boolean CheckType(Object arg, Class<?> clz)
    {
        boolean result;
        if(arg == null)
            return false;
        else {
            try {
                clz.cast(arg);
                result = true;
            }catch(ClassCastException e)
            {
                result = false;
            }
        }

        return result;
    }

    protected void OutputByteArray(StringBuffer outputStr, byte[] param)
    {

        if(param == null) {
            outputStr.append(" null") ;
            return;
        }

        outputStr.append(String.format("length:%d ", param.length));
        for(int bi=0;bi< (param.length>300?300:param.length);bi++) {
            outputStr.append(Integer.toString(param[bi] >> 4 & 0xF, 16));
            outputStr.append(Integer.toString(param[bi] & 0xF, 16));
        }
        String str = new String(param);

        if(str.length() <= 300)
            outputStr.append(" \t" + str);
        else
            outputStr.append(" \t" + str.substring(0,300));

    }

    protected void TryOutputParamOrResult(StringBuffer outputStr,
                                          Object obj, String paramtag, int i) throws Throwable
    {
        if(obj == null)
        {
            outputStr.append("\n | " + paramtag + " " + Integer.toString(i) + ": "
                    +  "null ");
            return;
        }
        else
        {
            outputStr.append( "\n | " + paramtag + " " + Integer.toString(i) + ": "
                    + obj.getClass().getName() + "\t ");
        }

        if(CheckType(obj, String.class))
        {
            outputStr.append((String)obj);

        }

        if(CheckType(obj, byte[].class))
        {
            OutputByteArray( outputStr, (byte[])obj);
        }else if(CheckType(obj, boolean.class))
        {
            outputStr.append((boolean)obj?"true":"false");

        }

        if(CheckType(obj, Integer.class))
        {
            outputStr.append(Integer.toString((Integer)obj));
        }else
        if(CheckType(obj, int.class))
        {
            outputStr.append(Integer.toString((Integer)obj));
        }
    }

    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);

        if(param.thisObject != null && !(param.thisObject instanceof Cipher))
        {
            return;
        }

        Cipher cipher = (Cipher)param.thisObject;
        if(!cipher.getProvider().getName().equals("BC") && cipher.getAlgorithm().indexOf("RSA") < 0)
            return;

        Throwable th = new Throwable();
        StackTraceElement[] stackTraces = th.getStackTrace();

        StringBuffer stackOutput = new StringBuffer("cyr HookMethodStackTraceAfter "
                + param.getClass().getName());

        if(stackTraces != null)
        {
            for(int i=0; i< (stackTraces.length < 20? stackTraces.length: 20); i++)
            {
                stackOutput.append(String.format("\n      StackTrace: %s #%s :%s",
                        stackTraces[i].getClassName(),
                        stackTraces[i].getMethodName(), stackTraces[i].getLineNumber()));

            }
            if(stackTraces.length >= 20)
            {
                stackOutput.append("\n      ....   ..... \n");
            }
        }

        //Log.i(tag, stackOutput.toString());

        Object methodResult = param.getResult();

        //StringBuffer outputStr;
        if(param.args == null)
            stackOutput.append("\nafter Call paramsLen: 0 ");
        else {
            stackOutput.append("\nafter Call paramsLen:" + param.args.length + " ");

            for (int i = 0; i < param.args.length; i++) {
                TryOutputParamOrResult(stackOutput, param.args[i], "param", i);

            }
        }
        if(param.args.length >= 2)
        {
            stackOutput.append("\n");
            if(CheckType(param.args[0], int.class)){
                int mode = (int)param.args[0];
                if (mode == 1)
                    stackOutput.append("ENCRYPT_MODE/PUBLIC_KEY ");
                if (mode == 2)
                    stackOutput.append("DECRYPT_MODE/PRIVATE_KEY ");
                if (mode == 3)
                    stackOutput.append("SECRET_KEY ");
                if (mode == 4)
                    stackOutput.append("UNWRAP_MODE ");
                if (mode == 5)
                    stackOutput.append("WRAP_MODE ");
            }

            if(CheckType(param.args[1], Key.class)){
                Key key = (Key)param.args[1];
                stackOutput.append(" Algorithm: "+ key.getAlgorithm() + " Key: ");
                OutputByteArray(stackOutput, key.getEncoded());
            }

        }
        if(param.args.length > 3 && CheckType(param.args[2], IvParameterSpec.class))
        {
            IvParameterSpec ivparam = (IvParameterSpec)param.args[2];
            stackOutput.append(" IV: ");
            OutputByteArray(stackOutput, ivparam.getIV());
        }

        TryOutputParamOrResult(stackOutput, methodResult, "result", 0);

        stackOutput.append("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
        Log.w(tag, stackOutput.toString());
        super.beforeHookedMethod(param);
    }

}
