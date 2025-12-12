/*
  Warnings:

  - Made the column `confidenceScore` on table `Detection` required. This step will fail if there are existing NULL values in that column.
  - Made the column `riskScore` on table `Detection` required. This step will fail if there are existing NULL values in that column.
  - Made the column `threatType` on table `Detection` required. This step will fail if there are existing NULL values in that column.
  - Made the column `threatSeverity` on table `Detection` required. This step will fail if there are existing NULL values in that column.
  - Made the column `explanation` on table `Detection` required. This step will fail if there are existing NULL values in that column.
  - Made the column `modelVotes` on table `Detection` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Detection" ADD COLUMN     "rawTelemetry" JSONB,
ADD COLUMN     "recommendedActions" JSONB,
ALTER COLUMN "confidenceScore" SET NOT NULL,
ALTER COLUMN "riskScore" SET NOT NULL,
ALTER COLUMN "threatType" SET NOT NULL,
ALTER COLUMN "threatSeverity" SET NOT NULL,
ALTER COLUMN "explanation" SET NOT NULL,
ALTER COLUMN "modelVotes" SET NOT NULL;

-- CreateIndex
CREATE INDEX "Detection_deviceId_createdAt_idx" ON "Detection"("deviceId", "createdAt");

-- CreateIndex
CREATE INDEX "Detection_threatSeverity_createdAt_idx" ON "Detection"("threatSeverity", "createdAt");
