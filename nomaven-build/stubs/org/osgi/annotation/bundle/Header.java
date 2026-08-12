package org.osgi.annotation.bundle;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.PACKAGE})
@Repeatable(Header.Headers.class)
public @interface Header {
    String name();
    String value();

    @Documented @Retention(RetentionPolicy.CLASS)
    @Target({ElementType.TYPE, ElementType.PACKAGE})
    @interface Headers { Header[] value(); }
}
