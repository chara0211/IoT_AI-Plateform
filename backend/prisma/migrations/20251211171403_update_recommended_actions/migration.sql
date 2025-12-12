/*
  Warnings:

  - Changed the type of `recommendedActions` on the `Detection` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "Detection" DROP COLUMN "recommendedActions",
ADD COLUMN     "recommendedActions" JSONB NOT NULL;
