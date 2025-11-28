package com.fintech.identity.service;

import com.fintech.identity.dto.DeviceInfo;
import com.fintech.identity.entity.Device;
import com.fintech.identity.entity.Device.DeviceType;
import com.fintech.identity.entity.User;
import com.fintech.identity.repository.DeviceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class DeviceService {

    private static final Logger logger = LoggerFactory.getLogger(DeviceService.class);

    private final DeviceRepository deviceRepository;

    public DeviceService(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }

    @Transactional
    public Device registerDevice(User user, DeviceInfo deviceInfo, String ipAddress) {
        if (deviceInfo == null || deviceInfo.getDeviceId() == null) {
            logger.warn("No device info provided for user: {}", user.getEmail());
            return null;
        }

        Optional<Device> existingDevice = deviceRepository.findByUserIdAndDeviceId(user.getId(), deviceInfo.getDeviceId());

        if (existingDevice.isPresent()) {
            Device device = existingDevice.get();
            updateDeviceInfo(device, deviceInfo, ipAddress);
            return deviceRepository.save(device);
        }

        Device newDevice = Device.builder()
                .user(user)
                .deviceId(deviceInfo.getDeviceId())
                .deviceName(deviceInfo.getDeviceName())
                .deviceType(parseDeviceType(deviceInfo.getDeviceType()))
                .osName(deviceInfo.getOsName())
                .osVersion(deviceInfo.getOsVersion())
                .appVersion(deviceInfo.getAppVersion())
                .fingerprint(deviceInfo.getFingerprint())
                .pushToken(deviceInfo.getPushToken())
                .lastIpAddress(ipAddress)
                .lastUsedAt(LocalDateTime.now())
                .isTrusted(false)
                .build();

        Device savedDevice = deviceRepository.save(newDevice);
        logger.info("Registered new device for user: {}, deviceId: {}", user.getEmail(), deviceInfo.getDeviceId());

        return savedDevice;
    }

    @Transactional
    public Device validateAndUpdateDevice(User user, DeviceInfo deviceInfo, String ipAddress) {
        if (deviceInfo == null || deviceInfo.getDeviceId() == null) {
            return null;
        }

        Optional<Device> deviceOptional = deviceRepository.findByUserIdAndDeviceId(user.getId(), deviceInfo.getDeviceId());

        if (deviceOptional.isEmpty()) {
            // New device - register it but mark as not trusted
            return registerDevice(user, deviceInfo, ipAddress);
        }

        Device device = deviceOptional.get();
        updateDeviceInfo(device, deviceInfo, ipAddress);
        return deviceRepository.save(device);
    }

    public boolean isKnownDevice(UUID userId, String deviceId) {
        return deviceRepository.existsByUserIdAndDeviceId(userId, deviceId);
    }

    public boolean isTrustedDevice(UUID userId, String deviceId) {
        Optional<Device> device = deviceRepository.findByUserIdAndDeviceId(userId, deviceId);
        return device.map(Device::getIsTrusted).orElse(false);
    }

    public List<Device> getUserDevices(UUID userId) {
        return deviceRepository.findByUserId(userId);
    }

    @Transactional
    public void markDeviceAsTrusted(UUID userId, String deviceId) {
        deviceRepository.findByUserIdAndDeviceId(userId, deviceId)
                .ifPresent(device -> {
                    device.setIsTrusted(true);
                    deviceRepository.save(device);
                    logger.info("Device marked as trusted for userId: {}, deviceId: {}", userId, deviceId);
                });
    }

    private void updateDeviceInfo(Device device, DeviceInfo deviceInfo, String ipAddress) {
        device.setLastUsedAt(LocalDateTime.now());
        device.setLastIpAddress(ipAddress);
        if (deviceInfo.getDeviceName() != null) {
            device.setDeviceName(deviceInfo.getDeviceName());
        }
        if (deviceInfo.getOsVersion() != null) {
            device.setOsVersion(deviceInfo.getOsVersion());
        }
        if (deviceInfo.getAppVersion() != null) {
            device.setAppVersion(deviceInfo.getAppVersion());
        }
        if (deviceInfo.getPushToken() != null) {
            device.setPushToken(deviceInfo.getPushToken());
        }
    }

    private DeviceType parseDeviceType(String deviceType) {
        if (deviceType == null) {
            return DeviceType.WEB;
        }
        try {
            return DeviceType.valueOf(deviceType.toUpperCase());
        } catch (IllegalArgumentException e) {
            return DeviceType.WEB;
        }
    }
}
