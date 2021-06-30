import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;


public class TimeCountProxyHandle implements InvocationHandler{

    private Object proxied;

    public TimeCountProxyHandle(Object obj){
        proxied = obj;
    }

    public Object invoke(Object proxy, Method method, Object[] args) throws InvocationTargetException, IllegalAccessException {
        long beginTime = System.currentTimeMillis();
        Object result = method.invoke(proxied, args);
        long endTime = System.currentTimeMillis();
        System.out.println(method.getName() + "耗时:" + (endTime - beginTime));
        return result;
    }
}
