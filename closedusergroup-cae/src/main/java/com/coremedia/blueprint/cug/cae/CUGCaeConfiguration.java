package com.coremedia.blueprint.cug.cae;

import com.coremedia.blueprint.base.settings.SettingsService;
import com.coremedia.blueprint.common.services.context.ContextHelper;
import com.coremedia.blueprint.cug.CUGAuthorityStrategy;
import com.coremedia.blueprint.cug.CUGConfiguration;
import com.coremedia.blueprint.cug.cae.interceptors.CUGAuthorizingHandlerInterceptor;
import com.coremedia.blueprint.cug.cae.validation.CUGVisibilityValidator;
import com.coremedia.blueprint.cug.search.CUGSolrFilterProviderImpl;
import com.coremedia.objectserver.dataviews.DataViewFactory;
import com.coremedia.springframework.customizer.Customize;
import com.coremedia.springframework.xml.ResourceAwareXmlBeanDefinitionReader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.web.client.RestTemplate;

@Configuration
@Import(
        value = {
                CUGConfiguration.class
        }
)
@ImportResource(reader = ResourceAwareXmlBeanDefinitionReader.class,
        value = {
                "classpath:/com/coremedia/blueprint/base/settings/impl/bpbase-settings-services.xml",
                "classpath:/framework/spring/blueprint-services.xml",
                "classpath:/com/coremedia/cae/dataview-services.xml"
        }
)
public class CUGCaeConfiguration {

  @Bean
  @Customize(value = "contentbeanValidatorList", mode = Customize.Mode.PREPEND)
  public CUGVisibilityValidator cugVisibilityValidator(CUGAuthorityStrategy closedUserGroupGatedContentStrategy, ContextHelper contextHelper) {
    return new CUGVisibilityValidator(closedUserGroupGatedContentStrategy, contextHelper);
  }

  @Bean
  @Customize("solrSearchFilters")
  public CUGSolrFilterProviderImpl cugSolrFilterProvider() {
    return new CUGSolrFilterProviderImpl();
  }

  @Bean
  @Customize(value = "handlerInterceptors", mode = Customize.Mode.PREPEND)
  public CUGAuthorizingHandlerInterceptor cugAuthorizingHandlerInterceptor(CUGAuthorityStrategy closedUserGroupGatedContentStrategy,
                                                                           SettingsService settingsService,
                                                                           DataViewFactory dataViewFactory) {
    return new CUGAuthorizingHandlerInterceptor(closedUserGroupGatedContentStrategy, settingsService, dataViewFactory);
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    return new CUGUserAuthenticationProvider();
  }

  @Bean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }
}
