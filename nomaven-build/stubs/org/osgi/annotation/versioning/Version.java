package org.osgi.annotation.versioning;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS) @Target({ElementType.PACKAGE, ElementType.TYPE})
public @interface Version { String value(); }
