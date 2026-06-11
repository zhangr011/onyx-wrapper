"use client";

import * as Yup from "yup";
import { FormikField } from "@/refresh-components/form/FormikField";
import { FormField } from "@/refresh-components/form/FormField";
import InputTypeIn from "@/refresh-components/inputs/InputTypeIn";
import InputFile from "@/refresh-components/inputs/InputFile";
import InlineExternalLink from "@/refresh-components/InlineExternalLink";
import { ImageGenFormWrapper } from "@/refresh-pages/admin/ImageGenerationPage/forms/ImageGenFormWrapper";
import {
  ImageGenFormBaseProps,
  ImageGenFormChildProps,
  ImageGenSubmitPayload,
} from "@/refresh-pages/admin/ImageGenerationPage/forms/types";
import { ImageProvider } from "@/refresh-pages/admin/ImageGenerationPage/constants";
import { ImageGenerationCredentials } from "@/refresh-pages/admin/ImageGenerationPage/svc";
import { ModelAccessField } from "@/sections/modals/llmConfig/shared";

const VERTEXAI_PROVIDER_NAME = "vertex_ai";
const VERTEXAI_DEFAULT_LOCATION = "global";

type AuthMode = "service_account" | "api_key";

// Vertex form values
interface VertexImageGenFormValues {
  auth_mode: AuthMode;
  custom_config: {
    vertex_credentials: string;
    vertex_location: string;
    api_key: string;
    vertex_project: string;
  };
  is_public: boolean;
  groups: number[];
  personas: number[];
}

const initialValues: VertexImageGenFormValues = {
  auth_mode: "api_key",
  custom_config: {
    vertex_credentials: "",
    vertex_location: VERTEXAI_DEFAULT_LOCATION,
    api_key: "",
    vertex_project: "",
  },
  is_public: true,
  groups: [],
  personas: [],
};

const validationSchema = Yup.object().shape({
  auth_mode: Yup.string().oneOf(["service_account", "api_key"]).required(),
  custom_config: Yup.object().shape({
    vertex_location: Yup.string().required("Location is required"),
    vertex_credentials: Yup.string().when("$authMode", {
      is: "service_account",
      then: (schema) => schema.required("Credentials file is required"),
    }),
    api_key: Yup.string().when("$authMode", {
      is: "api_key",
      then: (schema) => schema.required("API key is required"),
    }),
    vertex_project: Yup.string().when("$authMode", {
      is: "api_key",
      then: (schema) => schema.required("Project ID is required"),
    }),
  }),
});

function getInitialValuesFromCredentials(
  credentials: ImageGenerationCredentials,
  _imageProvider: ImageProvider
): Partial<VertexImageGenFormValues> {
  const hasApiKey = !!credentials.custom_config?.api_key;
  return {
    auth_mode: hasApiKey ? "api_key" : "service_account",
    custom_config: {
      vertex_credentials: credentials.custom_config?.vertex_credentials || "",
      vertex_location:
        credentials.custom_config?.vertex_location || VERTEXAI_DEFAULT_LOCATION,
      api_key: credentials.custom_config?.api_key || "",
      vertex_project: credentials.custom_config?.vertex_project || "",
    },
    is_public: true,
    groups: [],
    personas: [],
  };
}

function transformValues(
  values: VertexImageGenFormValues,
  imageProvider: ImageProvider
): ImageGenSubmitPayload {
  const customConfig: Record<string, string> = {
    vertex_location: values.custom_config.vertex_location,
  };

  if (values.auth_mode === "api_key") {
    customConfig.api_key = values.custom_config.api_key;
    customConfig.vertex_project = values.custom_config.vertex_project;
  } else {
    customConfig.vertex_credentials = values.custom_config.vertex_credentials;
  }

  return {
    modelName: imageProvider.model_name,
    imageProviderId: imageProvider.image_provider_id,
    provider: VERTEXAI_PROVIDER_NAME,
    customConfig,
    isPublic: values.is_public,
    groups: values.groups,
    personas: values.personas,
  };
}

function VertexFormFields(
  props: ImageGenFormChildProps<VertexImageGenFormValues>
) {
  const { values, setFieldValue, apiStatus, showApiMessage, errorMessage, disabled, imageProvider } =
    props;

  const isApiKeyMode = values.auth_mode === "api_key";

  return (
    <>
      {/* Auth mode toggle */}
      <FormikField<AuthMode>
        name="auth_mode"
        render={(field, helper, meta, state) => (
          <FormField
            name="auth_mode"
            state={state}
            className="w-full"
          >
            <FormField.Label>Authentication Method</FormField.Label>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => helper.setValue("api_key")}
                className={`px-3 py-1.5 rounded text-sm ${
                  isApiKeyMode
                    ? "bg-blue-600 text-white"
                    : "bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-300"
                }`}
                disabled={disabled}
              >
                API Key
              </button>
              <button
                type="button"
                onClick={() => helper.setValue("service_account")}
                className={`px-3 py-1.5 rounded text-sm ${
                  !isApiKeyMode
                    ? "bg-blue-600 text-white"
                    : "bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-300"
                }`}
                disabled={disabled}
              >
                Service Account
              </button>
            </div>
            <FormField.Message
              messages={{
                idle: isApiKeyMode
                  ? "Use a Vertex AI Agent Platform API key."
                  : "Use a Google Cloud service account JSON file.",
                error: meta.error,
              }}
            />
          </FormField>
        )}
      />

      {isApiKeyMode ? (
        <>
          {/* API Key field */}
          <FormikField<string>
            name="custom_config.api_key"
            render={(field, helper, meta, state) => (
              <FormField
                name="custom_config.api_key"
                state={apiStatus === "error" ? "error" : state}
                className="w-full"
              >
                <FormField.Label>API Key</FormField.Label>
                <FormField.Control>
                  <InputTypeIn
                    value={field.value}
                    onChange={(e) => helper.setValue(e.target.value)}
                    onBlur={field.onBlur}
                    placeholder="AQ.xxx..."
                    showClearButton={true}
                    variant={disabled ? "disabled" : undefined}
                  />
                </FormField.Control>
                <FormField.Message
                  messages={{
                    idle: "Your Vertex AI API key from the Agent Platform.",
                    error: meta.error,
                  }}
                />
              </FormField>
            )}
          />

          {/* Project ID field */}
          <FormikField<string>
            name="custom_config.vertex_project"
            render={(field, helper, meta, state) => (
              <FormField
                name="custom_config.vertex_project"
                state={state}
                className="w-full"
              >
                <FormField.Label>Project ID</FormField.Label>
                <FormField.Control>
                  <InputTypeIn
                    value={field.value}
                    onChange={(e) => helper.setValue(e.target.value)}
                    onBlur={field.onBlur}
                    placeholder="my-gcp-project-123"
                    showClearButton={true}
                    variant={disabled ? "disabled" : undefined}
                  />
                </FormField.Control>
                <FormField.Message
                  messages={{
                    idle: "Your Google Cloud project ID.",
                    error: meta.error,
                  }}
                />
              </FormField>
            )}
          />
        </>
      ) : (
        /* Credentials File field (service account mode) */
        <FormikField<string>
          name="custom_config.vertex_credentials"
          render={(field, helper, meta, state) => (
            <FormField
              name="custom_config.vertex_credentials"
              state={apiStatus === "error" ? "error" : state}
              className="w-full"
            >
              <FormField.Label>Credentials File</FormField.Label>
              <FormField.Control>
                <InputFile
                  setValue={(value) => helper.setValue(value)}
                  error={apiStatus === "error"}
                  onBlur={field.onBlur}
                  showClearButton={true}
                  disabled={disabled}
                  accept="application/json"
                  placeholder="Upload or paste your credentials"
                />
              </FormField.Control>
              {showApiMessage ? (
                <FormField.APIMessage
                  state={apiStatus}
                  messages={{
                    loading: `Testing credentials with ${imageProvider.title}...`,
                    success: "Credentials valid. Configuration saved.",
                    error: errorMessage || "Invalid credentials",
                  }}
                />
              ) : (
                <FormField.Message
                  messages={{
                    idle: (
                      <>
                        {"Upload or paste your "}
                        <InlineExternalLink href="https://console.cloud.google.com/projectselector2/iam-admin/serviceaccounts?supportedpurview=project">
                          service account credentials
                        </InlineExternalLink>
                        {" from Google Cloud."}
                      </>
                    ),
                    error: meta.error,
                  }}
                />
              )}
            </FormField>
          )}
        />
      )}

      {/* Location field (shared) */}
      <FormikField<string>
        name="custom_config.vertex_location"
        render={(field, helper, meta, state) => (
          <FormField
            name="custom_config.vertex_location"
            state={state}
            className="w-full"
          >
            <FormField.Label>Location</FormField.Label>
            <FormField.Control>
              <InputTypeIn
                value={field.value}
                onChange={(e) => helper.setValue(e.target.value)}
                onBlur={field.onBlur}
                placeholder="us-central1"
                showClearButton={false}
                variant={disabled ? "disabled" : undefined}
              />
            </FormField.Control>
            <FormField.Message
              messages={{
                idle: (
                  <>
                    {"The Google Cloud region for your Vertex AI models. See "}
                    <InlineExternalLink href="https://cloud.google.com/vertex-ai/generative-ai/docs/learn/locations">
                      Google&apos;s documentation
                    </InlineExternalLink>
                    {" for available regions."}
                  </>
                ),
                error: meta.error,
              }}
            />
          </FormField>
        )}
      />
      <ModelAccessField />
    </>
  );
}

export function VertexImageGenForm(props: ImageGenFormBaseProps) {
  const { imageProvider, existingConfig } = props;

  return (
    <ImageGenFormWrapper<VertexImageGenFormValues>
      {...props}
      title={
        existingConfig
          ? `Edit ${imageProvider.title}`
          : `Connect ${imageProvider.title}`
      }
      description={imageProvider.description}
      initialValues={initialValues}
      validationSchema={validationSchema}
      getInitialValuesFromCredentials={getInitialValuesFromCredentials}
      transformValues={(values) => transformValues(values, imageProvider)}
    >
      {(childProps) => <VertexFormFields {...childProps} />}
    </ImageGenFormWrapper>
  );
}
