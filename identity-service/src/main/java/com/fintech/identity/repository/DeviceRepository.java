package com.fintech.identity.repository;

import com.fintech.identity.entity.Device;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface DeviceRepository extends JpaRepository<Device, UUID> {
    
    List<Device> findByUserId(UUID userId);
    
    Optional<Device> findByUserIdAndDeviceId(UUID userId, String deviceId);
    
    boolean existsByUserIdAndDeviceId(UUID userId, String deviceId);
    
    Optional<Device> findByUserIdAndFingerprint(UUID userId, String fingerprint);
}
