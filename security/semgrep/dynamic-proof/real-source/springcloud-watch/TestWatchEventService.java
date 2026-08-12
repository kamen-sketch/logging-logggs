// Stand-in for org.apache.logging.log4j.spring.cloud.config.client.WatchEventManager
// (log4j-spring-cloud-config-client), discovered via the exact same real
// ServiceLoader mechanism (WatchManager.java:142,
// ServiceLoader.load(WatchEventService.class)) rather than a description of
// how it's supposed to work. Mirrors that real class's own implementation
// almost line for line -- a static registry of subscribed WatchManagers, and
// a static publishEvent() that calls checkFiles() on all of them, which is
// exactly what Log4j2EventListener.onApplicationEvent() calls in response to
// a real Spring EnvironmentChangeEvent (fired by, among other things,
// Spring Boot Actuator's /actuator/refresh endpoint).

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.logging.log4j.core.util.WatchEventService;
import org.apache.logging.log4j.core.util.WatchManager;

public class TestWatchEventService implements WatchEventService {
    private static final ConcurrentMap<UUID, WatchManager> watchManagers = new ConcurrentHashMap<>();

    public static void publishEvent() {
        for (WatchManager manager : watchManagers.values()) {
            manager.checkFiles();
        }
    }

    @Override
    public void subscribe(final WatchManager manager) {
        watchManagers.put(manager.getId(), manager);
    }

    @Override
    public void unsubscribe(final WatchManager manager) {
        watchManagers.remove(manager.getId());
    }
}
