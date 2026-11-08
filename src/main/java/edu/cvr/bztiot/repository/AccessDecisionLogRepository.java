package edu.cvr.bztiot.repository;

import edu.cvr.bztiot.model.AccessDecisionLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccessDecisionLogRepository extends JpaRepository<AccessDecisionLog, Long> {

    /** Most recent 50 decisions for a specific device. */
    List<AccessDecisionLog> findTop50ByDeviceCodeOrderByDecidedAtDesc(String deviceCode);

    /** Most recent 20 decisions across all devices — for the dashboard. */
    List<AccessDecisionLog> findTop20ByOrderByDecidedAtDesc();

    /** All DENY or QUARANTINE decisions — used for the alerts page. */
    List<AccessDecisionLog> findByDecisionInOrderByDecidedAtDesc(List<String> decisions);
}
