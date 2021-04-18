use crate::api::{metadata::TypeMeta, GroupVersionKind, Resource};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{APIResource, APIResourceList, ObjectMeta};
use std::borrow::Cow;

/// Contains information about Kubernetes API resources
/// which is enough for working with it.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ApiResource {
    /// Resource group, empty for core group.
    pub group: String,
    /// group version
    pub version: String,
    /// apiVersion of the resource (v1 for core group,
    /// groupName/groupVersions for other).
    pub api_version: String,
    /// Singular PascalCase name of the resource
    pub kind: String,
    /// Plural name of the resource
    pub plural: String,
}

impl ApiResource {
    /// Creates ApiResource from `meta::v1::APIResource` instance.
    /// This is recommended way to create `ApiResource`s.
    /// This function correctly sets all fields except `subresources`.
    ///
    /// `APIResource` objects can be extracted from [`Client::list_api_group_resources`](crate::Client::list_api_group_resources).
    /// If it does not specify version and/or group, they will be taken from `group_version`
    /// (otherwise the second parameter is ignored).
    ///
    /// ### Example usage:
    /// ```
    /// use kube::api::{GroupVersionKind, Api, DynamicObject};
    /// # async fn scope(client: kube::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let apps = client.list_api_group_resources("apps/v1").await?;
    /// for ar in &apps.resources {
    ///     let gvk = GroupVersionKind::from_api_resource(ar, &apps.group_version);
    ///     dbg!(&gvk);
    ///     let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), "default", &gvk);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_apiresource(ar: &APIResource, group_version: &str) -> Self {
        let gvsplit = group_version.splitn(2, '/').collect::<Vec<_>>();
        let (default_group, default_version) = match *gvsplit.as_slice() {
            [g, v] => (g, v), // standard case
            [v] => ("", v),   // core v1 case
            _ => unreachable!(),
        };
        let group = ar.group.clone().unwrap_or_else(|| default_group.into());
        let version = ar.version.clone().unwrap_or_else(|| default_version.into());
        let kind = ar.kind.to_string();
        let api_version = if group.is_empty() {
            version.clone()
        } else {
            format!("{}/{}", group, version)
        };
        let plural = ar.name.clone();
        ApiResource {
            group,
            version,
            kind,
            api_version,
            plural,
        }
    }

    /// Creates ApiResource by type-erasing another Resource
    pub fn erase<K: Resource>(dt: &K::DynamicType) -> Self {
        ApiResource {
            group: K::group(dt).to_string(),
            version: K::version(dt).to_string(),
            api_version: K::api_version(dt).to_string(),
            kind: K::kind(dt).to_string(),
            plural: K::plural(dt).to_string(),
        }
    }

    /// Creates ApiResource from group, version and kind.
    /// # Warning
    /// This function has to **guess** resource plural name.
    /// While it makes it best to guess correctly, sometimes it can
    /// be wrong, and using returned ApiResource will lead to incorrect
    /// api requests.
    pub fn from_gvk(gvk: &GroupVersionKind) -> Self {
        let api_version = match gvk.group.as_str() {
            "" => gvk.version.clone(),
            _ => format!("{}/{}", gvk.group, gvk.version),
        };
        ApiResource {
            group: gvk.group.clone(),
            version: gvk.version.clone(),
            api_version,
            kind: gvk.kind.clone(),
            plural: crate::api::metadata::to_plural(&gvk.kind.to_ascii_lowercase()),
        }
    }
}

/// A dynamic representation of a kubernetes object
///
/// This will work with any non-list type object.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DynamicObject {
    /// The type fields, not always present
    #[serde(flatten, default)]
    pub types: Option<TypeMeta>,
    /// Object metadata
    pub metadata: ObjectMeta,

    /// All other keys
    #[serde(flatten)]
    pub data: serde_json::Value,
}

impl DynamicObject {
    /// Create a DynamicObject with minimal values set from ApiResource.
    pub fn new(name: &str, resource: &ApiResource) -> Self {
        Self {
            types: Some(TypeMeta {
                api_version: resource.api_version.to_string(),
                kind: resource.kind.to_string(),
            }),
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            data: Default::default(),
        }
    }

    /// Attach dynamic data to a DynamicObject
    pub fn data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }

    /// Attach a namespace to a DynamicObject
    pub fn within(mut self, ns: &str) -> Self {
        self.metadata.namespace = Some(ns.into());
        self
    }
}

impl Resource for DynamicObject {
    type DynamicType = ApiResource;

    fn group(dt: &ApiResource) -> Cow<'_, str> {
        dt.group.as_str().into()
    }

    fn version(dt: &ApiResource) -> Cow<'_, str> {
        dt.version.as_str().into()
    }

    fn kind(dt: &ApiResource) -> Cow<'_, str> {
        dt.kind.as_str().into()
    }

    fn api_version(dt: &ApiResource) -> Cow<'_, str> {
        dt.api_version.as_str().into()
    }

    fn plural(dt: &ApiResource) -> Cow<'_, str> {
        dt.plural.as_str().into()
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}

/// Resource scope
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Scope {
    /// Objects are global
    Cluster,
    /// Each object lives in namespace.
    Namespaced,
}

/// Operations that are supported on the resource
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Operations {
    /// Object can be created
    pub create: bool,
    /// Single object can be queried
    pub get: bool,
    /// Multiple objects can be queried
    pub list: bool,
    /// A watch can be started
    pub watch: bool,
    /// A single object can be deleted
    pub delete: bool,
    /// Multiple objects can be deleted
    pub delete_collection: bool,
    /// Object can be updated
    pub update: bool,
    /// Object can be patched
    pub patch: bool,
    /// All other verbs
    pub other: Vec<String>,
}

impl Operations {
    /// Returns empty `Operations`
    pub fn empty() -> Self {
        Operations {
            create: false,
            get: false,
            list: false,
            watch: false,
            delete: false,
            delete_collection: false,
            update: false,
            patch: false,
            other: Vec::new(),
        }
    }
}
/// Contains additional, detailed information abount API resource
pub struct ApiResourceExtras {
    /// Scope of the resource
    pub scope: Scope,
    /// Available subresources. Please note that returned ApiResources are not
    /// standalone resources. Their name will be of form `subresource_name`,
    /// not `resource_name/subresource_name`.
    /// To work with subresources, use `Request` methods.
    pub subresources: Vec<(ApiResource, ApiResourceExtras)>,
    /// Supported operations on this resource
    pub operations: Operations,
}

impl ApiResourceExtras {
    /// Creates ApiResourceExtras from `meta::v1::APIResourceList` instance.
    /// This function correctly sets all fields except `subresources`.
    /// # Panics
    /// Panics if list does not contain resource named `name`.
    pub fn from_apiresourcelist(list: &APIResourceList, name: &str) -> Self {
        let ar = list
            .resources
            .iter()
            .find(|r| r.name == name)
            .expect("resource not found in APIResourceList");
        let scope = if ar.namespaced {
            Scope::Namespaced
        } else {
            Scope::Cluster
        };
        let mut operations = Operations::empty();
        for verb in &ar.verbs {
            match verb.as_str() {
                "create" => operations.create = true,
                "get" => operations.get = true,
                "list" => operations.list = true,
                "watch" => operations.watch = true,
                "delete" => operations.delete = true,
                "deletecollection" => operations.delete_collection = true,
                "update" => operations.update = true,
                "patch" => operations.patch = true,
                _ => operations.other.push(verb.clone()),
            }
        }
        let mut subresources = Vec::new();
        let subresource_name_prefix = format!("{}/", name);
        for res in &list.resources {
            if let Some(subresource_name) = res.name.strip_prefix(&subresource_name_prefix) {
                let mut api_resource = ApiResource::from_apiresource(res, &list.group_version);
                api_resource.plural = subresource_name.to_string();
                let extra = ApiResourceExtras::from_apiresourcelist(list, &res.name);
                subresources.push((api_resource, extra));
            }
        }

        ApiResourceExtras {
            scope,
            subresources,
            operations,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        api::{
            ApiResource, DynamicObject, GroupVersionKind, Patch, PatchParams, PostParams, Request, Resource,
        },
        Result,
    };
    #[test]
    fn raw_custom_resource() {
        let gvk = GroupVersionKind::gvk("clux.dev", "v1", "Foo").unwrap();
        let res = ApiResource::from_gvk(&gvk);
        let url = DynamicObject::url_path(&res, Some("myns"));

        let pp = PostParams::default();
        let req = Request::new(&url).create(&pp, vec![]).unwrap();
        assert_eq!(req.uri(), "/apis/clux.dev/v1/namespaces/myns/foos?");
        let patch_params = PatchParams::default();
        let req = Request::new(url)
            .patch("baz", &patch_params, &Patch::Merge(()))
            .unwrap();
        assert_eq!(req.uri(), "/apis/clux.dev/v1/namespaces/myns/foos/baz?");
        assert_eq!(req.method(), "PATCH");
    }

    #[test]
    fn raw_resource_in_default_group() -> Result<()> {
        let gvk = GroupVersionKind::gvk("", "v1", "Service").unwrap();
        let api_resource = ApiResource::from_gvk(&gvk);
        let url = DynamicObject::url_path(&api_resource, None);
        let pp = PostParams::default();
        let req = Request::new(url).create(&pp, vec![])?;
        assert_eq!(req.uri(), "/api/v1/services?");
        Ok(())
    }

    #[cfg(feature = "derive")]
    #[tokio::test]
    #[ignore] // circle has no kubeconfig
    async fn convenient_custom_resource() {
        use crate as kube; // derive macro needs kube in scope
        use crate::{Api, Client, CustomResource};
        use schemars::JsonSchema;
        use serde::{Deserialize, Serialize};
        #[derive(Clone, Debug, CustomResource, Deserialize, Serialize, JsonSchema)]
        #[kube(group = "clux.dev", version = "v1", kind = "Foo", namespaced)]
        struct FooSpec {
            foo: String,
        }
        let client = Client::try_default().await.unwrap();

        let gvk = GroupVersionKind::gvk("clux.dev", "v1", "Foo").unwrap();
        let api_resource = ApiResource::from_gvk(&gvk);
        let a1: Api<DynamicObject> = Api::namespaced_with(client.clone(), "myns", &api_resource);
        let a2: Api<Foo> = Api::namespaced(client.clone(), "myns");

        // make sure they return the same url_path through their impls
        assert_eq!(a1.request.url_path, a2.request.url_path);
    }
}
