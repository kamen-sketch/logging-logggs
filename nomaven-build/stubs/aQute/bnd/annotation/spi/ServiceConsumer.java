package aQute.bnd.annotation.spi;
import aQute.bnd.annotation.*;
import java.lang.annotation.*;
@Documented @Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.PACKAGE})
@Repeatable(ServiceConsumer.ServiceConsumers.class)
public @interface ServiceConsumer {
    Class<?> value();
    Resolution resolution() default Resolution.MANDATORY;
    Cardinality cardinality() default Cardinality.SINGLE;
    String[] attribute() default {};
    @Documented @Retention(RetentionPolicy.CLASS) @Target({ElementType.TYPE, ElementType.PACKAGE})
    @interface ServiceConsumers { ServiceConsumer[] value(); }
}
