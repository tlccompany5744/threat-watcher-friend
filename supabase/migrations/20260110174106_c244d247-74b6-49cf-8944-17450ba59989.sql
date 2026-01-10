-- Create storage bucket for campaign attachments
INSERT INTO storage.buckets (id, name, public)
VALUES ('campaign-attachments', 'campaign-attachments', false)
ON CONFLICT (id) DO NOTHING;

-- Allow authenticated users to upload attachments
CREATE POLICY "Users can upload campaign attachments"
ON storage.objects FOR INSERT
WITH CHECK (
  bucket_id = 'campaign-attachments' 
  AND auth.uid() IS NOT NULL
);

-- Allow authenticated users to read their campaign attachments
CREATE POLICY "Users can read campaign attachments"
ON storage.objects FOR SELECT
USING (
  bucket_id = 'campaign-attachments' 
  AND auth.uid() IS NOT NULL
);

-- Allow authenticated users to delete their campaign attachments
CREATE POLICY "Users can delete campaign attachments"
ON storage.objects FOR DELETE
USING (
  bucket_id = 'campaign-attachments' 
  AND auth.uid() IS NOT NULL
);

-- Add attachment columns to phishing_campaigns table
ALTER TABLE public.phishing_campaigns 
ADD COLUMN IF NOT EXISTS attachment_path TEXT,
ADD COLUMN IF NOT EXISTS attachment_name TEXT;