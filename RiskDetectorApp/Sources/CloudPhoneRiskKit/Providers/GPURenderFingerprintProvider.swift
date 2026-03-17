#if canImport(Metal) && canImport(UIKit)
import CryptoKit
import Foundation
import Metal

final class GPURenderFingerprintProvider: RiskSignalProvider {
    static let shared = GPURenderFingerprintProvider()
    let id = "gpu_render_fingerprint"

    private let lock = NSLock()
    private var cachedFingerprint: String?
    private var cacheTime: TimeInterval = 0
    private let cacheTTL: TimeInterval = 300

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        guard let fp = fingerprint() else {
            return [RiskSignal(
                id: SignalID.gpuRenderUnavailable,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["detail": "metal_compute_failed"],
                state: .soft(confidence: 0.5),
                layer: 1,
                weightHint: 70
            )]
        }

        return [RiskSignal(
            id: SignalID.gpuRenderFingerprint,
            category: SignalCategory.cloudphone,
            score: 0,
            evidence: ["fingerprint": fp],
            state: .hard(detected: false),
            layer: 1,
            weightHint: 85
        )]
    }

    private func fingerprint() -> String? {
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock()
        if now - cacheTime < cacheTTL, let cached = cachedFingerprint {
            lock.unlock()
            return cached
        }
        lock.unlock()

        guard let result = renderFingerprint() else { return nil }

        lock.lock()
        cachedFingerprint = result
        cacheTime = ProcessInfo.processInfo.systemUptime
        lock.unlock()
        return result
    }

    private func renderFingerprint() -> String? {
        guard let device = MTLCreateSystemDefaultDevice(),
              let queue = device.makeCommandQueue(),
              let buffer = queue.makeCommandBuffer() else {
            return nil
        }

        let desc = MTLTextureDescriptor.texture2DDescriptor(
            pixelFormat: .rgba8Unorm,
            width: 8,
            height: 8,
            mipmapped: false
        )
        desc.usage = [.shaderRead, .shaderWrite]
        guard let texture = device.makeTexture(descriptor: desc) else { return nil }

        let source = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void fp_kernel(texture2d<float, access::write> out [[texture(0)]],
                              uint2 gid [[thread_position_in_grid]]) {
            float x = float(gid.x) / 7.0;
            float y = float(gid.y) / 7.0;
            float r = sin(x * 3.14159265 * 2.0 + y) * 0.5 + 0.5;
            float g = cos(y * 3.14159265 * 3.0 - x) * 0.5 + 0.5;
            float b = sin((x + y) * 3.14159265 * 1.5) * 0.5 + 0.5;
            out.write(float4(r, g, b, 1.0), gid);
        }
        """

        guard let library = try? device.makeLibrary(source: source, options: nil),
              let function = library.makeFunction(name: "fp_kernel"),
              let pipeline = try? device.makeComputePipelineState(function: function) else {
            return nil
        }

        guard let encoder = buffer.makeComputeCommandEncoder() else { return nil }
        encoder.setComputePipelineState(pipeline)
        encoder.setTexture(texture, index: 0)

        let threadgroupSize = MTLSize(width: 8, height: 8, depth: 1)
        let threadgroups = MTLSize(width: 1, height: 1, depth: 1)
        encoder.dispatchThreadgroups(threadgroups, threadsPerThreadgroup: threadgroupSize)
        encoder.endEncoding()

        buffer.commit()

        let semaphore = DispatchSemaphore(value: 0)
        buffer.addCompletedHandler { _ in semaphore.signal() }
        if semaphore.wait(timeout: .now() + 3.0) == .timedOut {
            return nil
        }

        guard buffer.status == .completed else { return nil }

        var pixels = [UInt8](repeating: 0, count: 8 * 8 * 4)
        texture.getBytes(
            &pixels,
            bytesPerRow: 8 * 4,
            from: MTLRegion(
                origin: MTLOrigin(x: 0, y: 0, z: 0),
                size: MTLSize(width: 8, height: 8, depth: 1)
            ),
            mipmapLevel: 0
        )

        let digest = SHA256.hash(data: Data(pixels))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
#else
import Foundation

final class GPURenderFingerprintProvider: RiskSignalProvider {
    static let shared = GPURenderFingerprintProvider()
    let id = "gpu_render_fingerprint"
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] { [] }
}
#endif
