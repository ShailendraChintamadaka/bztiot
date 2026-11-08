package edu.cvr.bztiot.repository;

import edu.cvr.bztiot.model.TrustScoreHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface TrustScoreHistoryRepository extends JpaRepository<TrustScoreHistory, Long> {

    /** Most recent 50 trust score entries for a device. Used on device detail page. */
    List<TrustScoreHistory> findTop50ByDeviceCodeOrderByRecordedAtDesc(String deviceCode);

    /** Trust history since a given time — used for trend analysis on the dashboard. */
    List<TrustScoreHistory> findByDeviceCodeAndRecordedAtAfterOrderByRecordedAtAsc(
            String deviceCode, Instant since);
}
