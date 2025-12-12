-- CreateTable
CREATE TABLE "Detection" (
    "id" SERIAL NOT NULL,
    "deviceId" TEXT NOT NULL,
    "deviceType" TEXT,
    "isAnomaly" BOOLEAN NOT NULL,
    "confidenceScore" DOUBLE PRECISION,
    "riskScore" INTEGER,
    "threatType" TEXT,
    "threatSeverity" TEXT,
    "explanation" TEXT,
    "modelVotes" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Detection_pkey" PRIMARY KEY ("id")
);
