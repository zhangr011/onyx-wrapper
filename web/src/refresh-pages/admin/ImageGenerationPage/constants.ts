export interface ImageProvider {
  image_provider_id: string; // Static unique key for UI-DB mapping
  model_name: string; // Actual model name for LLM API
  provider_name: string;
  title: string;
  description: string;
}

export interface ProviderGroup {
  name: string;
  providers: ImageProvider[];
}

export const IMAGE_PROVIDER_GROUPS: ProviderGroup[] = [
  {
    name: "OpenAI",
    providers: [
      {
        image_provider_id: "openai_gpt_image_2",
        model_name: "gpt-image-2",
        provider_name: "openai",
        title: "GPT Image 2",
        description:
          "OpenAI's latest Image Generation model with the highest prompt fidelity.",
      },
      {
        image_provider_id: "openai_gpt_image_1_5",
        model_name: "gpt-image-1.5",
        provider_name: "openai",
        title: "GPT Image 1.5",
        description: "OpenAI's previous flagship Image Generation model.",
      },
      {
        image_provider_id: "openai_gpt_image_1",
        model_name: "gpt-image-1",
        provider_name: "openai",
        title: "GPT Image 1",
        description:
          "A capable image generation model from OpenAI with strong prompt adherence.",
      },
    ],
  },
  {
    name: "Azure OpenAI",
    providers: [
      {
        image_provider_id: "azure_gpt_image_2",
        model_name: "", // Extracted from deployment in target URI
        provider_name: "azure",
        title: "Azure OpenAI GPT Image 2",
        description:
          "GPT Image 2 image generation model hosted on Microsoft Azure.",
      },
      {
        image_provider_id: "azure_gpt_image_1_5",
        model_name: "", // Extracted from deployment in target URI
        provider_name: "azure",
        title: "Azure OpenAI GPT Image 1.5",
        description:
          "GPT Image 1.5 image generation model hosted on Microsoft Azure.",
      },
      {
        image_provider_id: "azure_gpt_image_1",
        model_name: "", // Extracted from deployment in target URI
        provider_name: "azure",
        title: "Azure OpenAI GPT Image 1",
        description:
          "GPT Image 1 image generation model hosted on Microsoft Azure.",
      },
    ],
  },
  {
    name: "Google Cloud Vertex AI",
    providers: [
      {
        image_provider_id: "gemini-2.5-flash-image",
        model_name: "gemini-2.5-flash-image",
        provider_name: "vertex_ai",
        title: "Gemini 2.5 Flash Image",
        description:
          "Gemini 2.5 Flash Image (Nano Banana) model is designed for speed and efficiency.",
      },
      {
        image_provider_id: "gemini-3-pro-image-preview",
        model_name: "gemini-3-pro-image-preview",
        provider_name: "vertex_ai",
        title: "Gemini 3 Pro Image Preview",
        description:
          "Gemini 3 Pro Image Preview (Nano Banana Pro) is designed for professional asset production.",
      },
    ],
  },
  {
    name: "Company API (qcai)",
    providers: [
      {
        image_provider_id: "qcai_gpt_image_2_1k",
        model_name: "gpt-image-2-1k",
        provider_name: "openai",
        title: "GPT Image 2 1K (Company)",
        description:
          "GPT Image 2 1K via company API endpoint (qcai.qcplay.com). Requires custom base URL.",
      },
      {
        image_provider_id: "qcai_gemini_3_pro_image_preview",
        model_name: "gemini-3-pro-image-preview",
        provider_name: "openai",
        title: "Gemini 3 Pro Image Preview (Company)",
        description:
          "Gemini 3 Pro Image Preview via company API endpoint (qcai.qcplay.com). Requires custom base URL.",
      },
    ],
  },
];
