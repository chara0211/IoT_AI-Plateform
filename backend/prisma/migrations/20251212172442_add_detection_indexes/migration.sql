-- CreateIndex
CREATE INDEX "Detection_createdAt_idx" ON "Detection"("createdAt");

-- CreateIndex
CREATE INDEX "Detection_isAnomaly_createdAt_idx" ON "Detection"("isAnomaly", "createdAt");
