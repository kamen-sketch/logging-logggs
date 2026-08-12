package org.jspecify.annotations;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE_USE})
public @interface NonNull {}
