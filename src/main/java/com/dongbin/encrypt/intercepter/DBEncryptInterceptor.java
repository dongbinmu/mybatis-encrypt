package com.dongbin.encrypt.intercepter;

import com.dongbin.encrypt.annotation.MybatisEncrypt;
import com.dongbin.encrypt.utils.AESUtil;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Plugin;
import org.apache.ibatis.plugin.Signature;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.springframework.stereotype.Component;
import org.springframework.util.ReflectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@Intercepts({@Signature(type = Executor.class, method = "update", args = {MappedStatement.class, Object.class}),
        @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class,
                RowBounds.class, ResultHandler.class})})
@Component
public class DBEncryptInterceptor implements Interceptor {

    @Override
    public Object intercept(Invocation invocation) throws Throwable {

        /**
         * encrypt
         */
        if ("update".equalsIgnoreCase(invocation.getMethod().getName())) {
            invocation.getArgs()[1] = handle(invocation.getArgs()[1], false);
        }

        /**
         * decrypt
         */
        Object returnValue = invocation.proceed();

        if (returnValue instanceof ArrayList) {
            List<?> list = (List<?>) returnValue;
            list.forEach(o -> handle(o, true));
        } else {
            handle(returnValue, true);
        }

        return returnValue;
    }

    private Object handle(Object o, boolean b) {
        if (o != null) {
            ReflectionUtils.doWithFields(o.getClass(), field -> {
                if (field.isAnnotationPresent(MybatisEncrypt.class) && field.get(o) != null) {
                    try {
                        String value = (String) field.get(o);
                        field.setAccessible(true);//accessible 是安全检查 用完后记得设置回false
                        field.set(o, b ? AESUtil.decrypt(value) : AESUtil.encrypt(value));
                        field.setAccessible(false);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        }
        return o;
    }

    @Override
    public Object plugin(Object o) {
        return Plugin.wrap(o, this);
    }

    @Override
    public void setProperties(Properties properties) {

    }
}
