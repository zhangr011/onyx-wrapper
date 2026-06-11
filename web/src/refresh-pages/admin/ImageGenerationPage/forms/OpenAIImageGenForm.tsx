"use client";

import React from "react";
import * as Yup from "yup";
import { FormikField } from "@/refresh-components/form/FormikField";
import { FormField } from "@/refresh-components/form/FormField";
import InputComboBox from "@/refresh-components/inputs/InputComboBox";
import PasswordInputTypeIn from "@/refresh-components/inputs/PasswordInputTypeIn";
import { ImageGenFormWrapper } from "@/refresh-pages/admin/ImageGenerationPage/forms/ImageGenFormWrapper";
import {
  ImageGenFormBaseProps,
  ImageGenFormChildProps,
  ImageGenSubmitPayload,
} from "@/refresh-pages/admin/ImageGenerationPage/forms/types";
import { ImageGenerationCredentials } from "@/refresh-pages/admin/ImageGenerationPage/svc";
import { ImageProvider } from "@/refresh-pages/admin/ImageGenerationPage/constants";
import { ModelAccessField } from "@/sections/modals/llmConfig/shared";

// OpenAI form values - API key + optional base URL + access control
interface OpenAIFormValues {
  api_key: string;
  api_base: string;
  is_public: boolean;
  groups: number[];
  personas: number[];
}

const initialValues: OpenAIFormValues = {
  api_key: "",
  api_base: "",
  is_public: true,
  groups: [],
  personas: [],
};

const validationSchema = Yup.object().shape({
  api_key: Yup.string().required("API Key is required"),
  api_base: Yup.string().optional(),
});

function OpenAIFormFields(props: ImageGenFormChildProps<OpenAIFormValues>) {
  const {
    apiStatus,
    showApiMessage,
    errorMessage,
    disabled,
    isLoadingCredentials,
    apiKeyOptions,
    resetApiState,
    imageProvider,
  } = props;

  return (
    <>
      <FormikField<string>
        name="api_key"
        render={(field, helper, meta, state) => (
          <FormField
            name="api_key"
            state={apiStatus === "error" ? "error" : state}
            className="w-full"
          >
            <FormField.Label>API Key</FormField.Label>
            <FormField.Control>
              {apiKeyOptions.length > 0 ? (
                <InputComboBox
                  value={field.value}
                  onChange={(e) => {
                    helper.setValue(e.target.value);
                    resetApiState();
                  }}
                  onValueChange={(value) => {
                    helper.setValue(value);
                    resetApiState();
                  }}
                  onBlur={field.onBlur}
                  options={apiKeyOptions}
                  placeholder={
                    isLoadingCredentials
                      ? "Loading..."
                      : "Enter new API key or select existing provider"
                  }
                  disabled={disabled}
                  isError={apiStatus === "error"}
                />
              ) : (
                <PasswordInputTypeIn
                  {...field}
                  onChange={(e) => {
                    field.onChange(e);
                    resetApiState();
                  }}
                  placeholder={
                    isLoadingCredentials ? "Loading..." : "Enter your API key"
                  }
                  showClearButton={false}
                  disabled={disabled}
                  error={apiStatus === "error"}
                />
              )}
            </FormField.Control>
            {showApiMessage ? (
              <FormField.APIMessage
                state={apiStatus}
                messages={{
                  loading: `Testing API key with ${imageProvider.title}...`,
                  success: "API key is valid. Configuration saved.",
                  error: errorMessage || "Invalid API key",
                }}
              />
            ) : (
              <FormField.Message
                messages={{
                  idle: "Enter a new API key or select an existing provider.",
                  error: meta.error,
                }}
              />
            )}
          </FormField>
        )}
      />
      <FormikField<string>
        name="api_base"
        render={(field, helper, meta, state) => (
          <FormField
            name="api_base"
            state={state}
            className="w-full"
          >
            <FormField.Label>Custom Base URL</FormField.Label>
            <FormField.Control>
              <input
                type="text"
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                placeholder="https://api.openai.com/v1 (leave empty for default)"
                {...field}
                disabled={disabled}
              />
            </FormField.Control>
            <FormField.Message
              messages={{
                idle: "Optional. Use a custom OpenAI-compatible endpoint.",
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

function getInitialValuesFromCredentials(
  credentials: ImageGenerationCredentials,
  _imageProvider: ImageProvider
): Partial<OpenAIFormValues> {
  return {
    api_key: credentials.api_key || "",
    api_base: credentials.api_base || "",
    // Note: Access control fields are not returned by the credentials endpoint
    // Use defaults when editing - user can adjust via ModelAccessField
    is_public: true,
    groups: [],
    personas: [],
  };
}

function transformValues(
  values: OpenAIFormValues,
  imageProvider: ImageProvider
): ImageGenSubmitPayload {
  return {
    modelName: imageProvider.model_name,
    imageProviderId: imageProvider.image_provider_id,
    provider: "openai",
    apiKey: values.api_key,
    apiBase: values.api_base || undefined,
    isPublic: values.is_public,
    groups: values.groups,
    personas: values.personas,
  };
}

export function OpenAIImageGenForm(props: ImageGenFormBaseProps) {
  const { imageProvider, existingConfig } = props;

  return (
    <ImageGenFormWrapper<OpenAIFormValues>
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
      {(childProps) => <OpenAIFormFields {...childProps} />}
    </ImageGenFormWrapper>
  );
}
